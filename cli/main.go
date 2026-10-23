// Command messh is the messh CLI: login, publish, resolve, verify, add,
// remove, sync and key management.
package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"messh.io/go/messh"

	"github.com/messhio/messh/cli/internal/apitypes"
	"github.com/messhio/messh/cli/internal/sshkeys"
)

var version = "dev"

const usage = `messh: your name, your keys.

Usage:
  messh login                         sign in (device code)
  messh logout
  messh publish [--key F] [--name N] [--agent A]...
  messh resolve <user> [--json]
  messh verify <user>
  messh add <user> [--user U] [--key N] [--fingerprint FP] [--yes] [--dry-run]
  messh remove <user> [--user U]
  messh sync [--user U]
  messh keys
  messh keys revoke <name> [--reason R]
  messh curl [-X M] [-d BODY] [-H 'K: V']... [--key F] [-v] <url>
                                      sign a request with Web Bot Auth
  messh version

Registry: $MESSH_REGISTRY, else the one you logged in to, else https://messh.io.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	cmds := map[string]func([]string) error{
		"login": cmdLogin, "logout": cmdLogout, "publish": cmdPublish,
		"resolve": cmdResolve, "verify": cmdVerify, "add": cmdAdd,
		"remove": cmdRemove, "sync": cmdSync, "keys": cmdKeys, "curl": cmdCurl,
		"version": func([]string) error { fmt.Println("messh", version); return nil },
	}
	cmd, ok := cmds[os.Args[1]]
	if !ok {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	if err := cmd(os.Args[2:]); err != nil {
		fmt.Fprintln(os.Stderr, "✗", err)
		os.Exit(1)
	}
}

// parse lets flags appear before or after positional arguments.
func parse(fs *flag.FlagSet, args []string) []string {
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			os.Exit(2)
		}
		args = fs.Args()
		if len(args) == 0 {
			return pos
		}
		pos, args = append(pos, args[0]), args[1:]
	}
}

func oneUser(name string, pos []string) (string, error) {
	if len(pos) != 1 {
		return "", fmt.Errorf("usage: messh %s <user>", name)
	}
	u := strings.ToLower(pos[0])
	if !apitypes.UsernameRe.MatchString(u) {
		return "", fmt.Errorf("%q is not a valid messh username", pos[0])
	}
	return u, nil
}

type multi []string

func (m *multi) String() string     { return strings.Join(*m, ",") }
func (m *multi) Set(v string) error { *m = append(*m, v); return nil }

// --- login / logout ---

func cmdLogin(args []string) error {
	parse(flag.NewFlagSet("login", flag.ExitOnError), args)
	c := newClient()
	c.token = ""
	host, _ := os.Hostname()
	var dc apitypes.DeviceCode
	if err := c.do("POST", "/api/v1/device/code", map[string]string{"client_name": host}, &dc); err != nil {
		return fmt.Errorf("registry %s: %w", c.base, err)
	}
	open := dc.VerificationURIComplete
	if open == "" {
		open = dc.VerificationURI
	}
	fmt.Printf("Open %s\nand confirm the code %s\n", open, dc.UserCode)
	interval := time.Duration(max(dc.Interval, 1)) * time.Second
	deadline := time.Now().Add(time.Duration(dc.ExpiresIn) * time.Second)
	for time.Now().Before(deadline) {
		time.Sleep(interval)
		var tok apitypes.DeviceToken
		err := c.do("POST", "/api/v1/device/token", map[string]string{"device_code": dc.DeviceCode}, &tok)
		var ae *apiError
		if errors.As(err, &ae) {
			switch ae.Body.Error {
			case "authorization_pending":
				continue
			case "slow_down":
				interval += 5 * time.Second
				continue
			case "access_denied":
				return errors.New("sign-in was denied in the browser")
			case "expired_token":
				return errors.New("the code expired; run messh login again")
			}
		}
		if err != nil {
			return err
		}
		if err := saveSession(config{Registry: c.base, Username: tok.Username}, tok.AccessToken); err != nil {
			return err
		}
		fmt.Printf("✓ Logged in as %s\n", tok.Username)
		return nil
	}
	return errors.New("device code expired; run messh login again")
}

func cmdLogout(args []string) error {
	parse(flag.NewFlagSet("logout", flag.ExitOnError), args)
	c := newClient()
	if c.token != "" {
		if err := c.do("POST", "/api/v1/logout", nil, nil); err != nil {
			fmt.Fprintln(os.Stderr, "! could not revoke the session on the registry:", err)
		}
	}
	os.Remove(filepath.Join(configDir(), "token"))
	fmt.Println("✓ Logged out")
	return nil
}

// --- publish ---

var nonLabel = regexp.MustCompile(`[^a-z0-9._-]+`)

func defaultKeyName() string {
	h, _ := os.Hostname()
	h, _, _ = strings.Cut(strings.ToLower(h), ".")
	h = strings.Trim(nonLabel.ReplaceAllString(h, "-"), "-._")
	if len(h) > 32 {
		h = h[:32]
	}
	if h == "" {
		return "default"
	}
	return h
}

func cmdPublish(args []string) error {
	fs := flag.NewFlagSet("publish", flag.ExitOnError)
	home, _ := os.UserHomeDir()
	keyPath := fs.String("key", filepath.Join(home, ".ssh", "id_ed25519.pub"), "path to a public key")
	name := fs.String("name", defaultKeyName(), "label for this key")
	var agents multi
	fs.Var(&agents, "agent", "agent using this key (repeatable)")
	parse(fs, args)

	c := newClient()
	if err := c.mustAuth(); err != nil {
		return err
	}
	data, err := os.ReadFile(*keyPath)
	if err != nil {
		return err
	}
	if sshkeys.LooksPrivate(data) {
		return fmt.Errorf("refusing to publish %s: it is a private key. Publish the .pub file; private keys never leave this machine", *keyPath)
	}
	k, err := sshkeys.ParsePublic(data)
	if err != nil {
		return err
	}

	var ch apitypes.Challenge
	if err := c.do("POST", "/api/v1/keys/challenge", apitypes.ChallengeRequest{PublicKey: k.Line}, &ch); err != nil {
		return err
	}
	// Sign with the private half next to the .pub, or via ssh-agent for the .pub alone.
	signer := strings.TrimSuffix(*keyPath, ".pub")
	if _, err := os.Stat(signer); err != nil || signer == *keyPath {
		signer = *keyPath
	}
	fmt.Printf("signing ownership challenge with %s…\n", signer)
	sig, err := sshSign(signer, ch.Namespace, ch.Message)
	if err != nil {
		return err
	}
	var key apitypes.Key
	if err := c.do("POST", "/api/v1/keys", apitypes.PublishRequest{
		ChallengeID: ch.ID, Signature: sig, Name: *name, Agents: agents,
	}, &key); err != nil {
		return err
	}
	fmt.Printf("✓ %s %s (%s)\n", key.Type, key.Fingerprint, key.Name)
	fmt.Printf("✓ Live at %s/%s\n", c.base, loadConfig().Username)
	return nil
}

// sshSign produces an armored SSHSIG with ssh-keygen, so any key ssh-keygen
// or ssh-agent can use (including hardware keys) works.
func sshSign(keyFile, namespace, message string) (string, error) {
	dir, err := os.MkdirTemp("", "messh-sign-")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(dir)
	msg := filepath.Join(dir, "challenge")
	if err := os.WriteFile(msg, []byte(message), 0o600); err != nil {
		return "", err
	}
	cmd := exec.Command("ssh-keygen", "-q", "-Y", "sign", "-n", namespace, "-f", keyFile, msg)
	cmd.Stdin, cmd.Stderr = os.Stdin, os.Stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("ssh-keygen -Y sign failed: %w", err)
	}
	sig, err := os.ReadFile(msg + ".sig")
	return string(sig), err
}

// --- resolve / verify ---

func linkedSummary(p *apitypes.Profile) string {
	var parts []string
	for _, l := range p.Linked {
		name := strings.ToUpper(l.Provider[:1]) + l.Provider[1:]
		if l.Login != "" {
			name += " " + l.Login
		}
		parts = append(parts, name+" ✓")
	}
	return strings.Join(parts, " · ")
}

func cmdResolve(args []string) error {
	fs := flag.NewFlagSet("resolve", flag.ExitOnError)
	asJSON := fs.Bool("json", false, "print the profile document")
	username, err := oneUser("resolve", parse(fs, args))
	if err != nil {
		return err
	}
	p, err := newClient().profile(username)
	if err != nil {
		return err
	}
	if *asJSON {
		e := json.NewEncoder(os.Stdout)
		e.SetIndent("", "  ")
		return e.Encode(p)
	}
	fmt.Printf("%s · %s\n", p.Username, linkedSummary(p))
	for _, k := range p.Keys {
		fmt.Printf("  %-12s %s  %s  verified\n", k.Type, k.Fingerprint, k.Name)
	}
	if len(p.Agents) > 0 {
		fmt.Printf("  agents: %s\n", strings.Join(p.Agents, ", "))
	}
	if len(p.Keys) == 0 {
		fmt.Println("  no keys published")
	}
	return nil
}

func cmdVerify(args []string) error {
	username, err := oneUser("verify", parse(flag.NewFlagSet("verify", flag.ExitOnError), args))
	if err != nil {
		return err
	}
	c := newClient()
	p, err := c.profile(username)
	if err != nil {
		return err
	}
	text, err := c.keysText(username)
	if err != nil {
		return err
	}
	failed := 0
	check := func(ok bool, msg string) {
		mark := "✓"
		if !ok {
			mark, failed = "✗", failed+1
		}
		fmt.Printf("%s %s\n", mark, msg)
	}
	check(p.Username == username, "document is for "+username)
	check(len(p.Linked) > 0, "linked account: "+linkedSummary(p))
	check(len(p.Keys) > 0, fmt.Sprintf("%d active key(s)", len(p.Keys)))
	revoked := map[string]bool{}
	for _, r := range p.Revoked {
		revoked[r.Fingerprint] = true
	}
	served := map[string]bool{}
	for _, raw := range strings.Split(strings.TrimSpace(text), "\n") {
		if l := parseLine(raw); l.blob != "" {
			served[l.blob] = true
		}
	}
	for _, k := range p.Keys {
		pk, err := sshkeys.ParsePublic([]byte(k.PublicKey))
		check(err == nil && pk.Fingerprint == k.Fingerprint, fmt.Sprintf("%s: fingerprint %s matches key", k.Name, k.Fingerprint))
		check(k.Possession, k.Name+": proof of possession")
		check(k.Status == "active" && !revoked[k.Fingerprint], k.Name+": not revoked")
		check(served[k.PublicKey], k.Name+": served in "+username+".keys")
	}
	check(len(served) == len(p.Keys), fmt.Sprintf("%s.keys has exactly the %d active key(s)", username, len(p.Keys)))
	if failed > 0 {
		return fmt.Errorf("verify %s: %d check(s) failed", username, failed)
	}
	fmt.Printf("✓ %s verified\n", username)
	return nil
}

// --- add / remove / sync ---

func confirm(prompt string) bool {
	in := os.Stdin
	if tty, err := os.Open("/dev/tty"); err == nil {
		defer tty.Close()
		in = tty
	}
	fmt.Print(prompt)
	line, _ := bufio.NewReader(in).ReadString('\n')
	return strings.EqualFold(strings.TrimSpace(line), "y") || strings.EqualFold(strings.TrimSpace(line), "yes")
}

func cmdAdd(args []string) error {
	fs := flag.NewFlagSet("add", flag.ExitOnError)
	unixUser := fs.String("user", "", "target Unix account (needs sudo)")
	file := fs.String("file", "", "authorized_keys file to edit")
	keyName := fs.String("key", "", "add only the key with this name")
	fingerprint := fs.String("fingerprint", "", "add only this exact key (SHA256:…)")
	yes := fs.Bool("yes", false, "don't prompt (scripts, cloud-init)")
	dryRun := fs.Bool("dry-run", false, "print, don't write")
	username, err := oneUser("add", parse(fs, args))
	if err != nil {
		return err
	}
	t, err := resolveTarget(*unixUser, *file)
	if err != nil {
		return err
	}
	p, err := newClient().profile(username)
	if err != nil {
		return err
	}

	var picked []apitypes.Key
	for _, k := range p.Keys {
		pk, err := sshkeys.ParsePublic([]byte(k.PublicKey))
		if err != nil || pk.Fingerprint != k.Fingerprint {
			return fmt.Errorf("registry served key %q whose fingerprint doesn't match; refusing", k.Name)
		}
		if (*keyName == "" || k.Name == *keyName) && (*fingerprint == "" || k.Fingerprint == *fingerprint) {
			picked = append(picked, k)
		}
	}
	if len(picked) == 0 {
		if *fingerprint != "" {
			return fmt.Errorf("%s has no active key %s; refusing (pinned fingerprint)", username, *fingerprint)
		}
		return fmt.Errorf("%s has no matching active keys", username)
	}
	fmt.Printf("%s · %d key(s)\n", username, len(picked))
	for _, k := range picked {
		fmt.Printf("  %-12s %s  %s\n", k.Type, k.Fingerprint, k.Name)
	}
	if *dryRun {
		fmt.Printf("dry run: would add to %s\n", t.path)
		return nil
	}
	if !*yes && !confirm(fmt.Sprintf("Add to %s? [y/N] ", t.path)) {
		return errors.New("aborted")
	}

	added, present := 0, 0
	err = t.edit(func(lines []akLine) []akLine {
		have := map[string]bool{}
		for _, l := range lines {
			if l.blob != "" {
				have[l.blob] = true
			}
		}
		for _, k := range picked {
			if have[k.PublicKey] {
				present++
				continue
			}
			lines = append(lines, parseLine(k.PublicKey+" "+tagFor(username, k.Name)))
			added++
		}
		return lines
	})
	if err != nil {
		return err
	}
	fmt.Printf("✓ Added %d key(s) (tagged messh:%s)", added, username)
	if present > 0 {
		fmt.Printf(", %d already present", present)
	}
	fmt.Println()
	return nil
}

func cmdRemove(args []string) error {
	fs := flag.NewFlagSet("remove", flag.ExitOnError)
	unixUser := fs.String("user", "", "target Unix account (needs sudo)")
	file := fs.String("file", "", "authorized_keys file to edit")
	username, err := oneUser("remove", parse(fs, args))
	if err != nil {
		return err
	}
	t, err := resolveTarget(*unixUser, *file)
	if err != nil {
		return err
	}
	removed := 0
	err = t.edit(func(lines []akLine) []akLine {
		return slices.DeleteFunc(lines, func(l akLine) bool {
			if l.tag != "" && l.owner == username {
				removed++
				return true
			}
			return false
		})
	})
	if err != nil {
		return err
	}
	fmt.Printf("✓ Removed %d key(s) tagged messh:%s; other lines untouched\n", removed, username)
	return nil
}

func cmdSync(args []string) error {
	fs := flag.NewFlagSet("sync", flag.ExitOnError)
	unixUser := fs.String("user", "", "target Unix account (needs sudo)")
	file := fs.String("file", "", "authorized_keys file to edit")
	parse(fs, args)
	t, err := resolveTarget(*unixUser, *file)
	if err != nil {
		return err
	}
	c := newClient()

	// Resolve every identity first, outside the lock.
	owners := map[string]bool{}
	nkeys := 0
	for _, l := range readLines(t.path) {
		if l.tag != "" {
			owners[l.owner] = true
			nkeys++
		}
	}
	active := map[string]map[string]bool{} // owner → active key blobs; missing = unreachable
	newKeys := 0
	for owner := range owners {
		p, err := c.profile(owner)
		if err != nil {
			fmt.Printf("! %s: lookup failed (%v); keeping cached keys\n", owner, err)
			continue
		}
		active[owner] = map[string]bool{}
		for _, k := range p.Keys {
			active[owner][k.PublicKey] = true
		}
		newKeys += len(p.Keys)
	}
	fmt.Printf("checked %d identities · %d keys\n", len(owners), nkeys)

	removed := 0
	err = t.edit(func(lines []akLine) []akLine {
		kept := 0
		lines = slices.DeleteFunc(lines, func(l akLine) bool {
			set, resolved := active[l.owner]
			if l.tag == "" || !resolved {
				return false // hand-added line, or registry unreachable: never remove
			}
			if !set[l.blob] {
				fmt.Printf("− removed %s (%s): no longer an active key\n", l.tag, strings.SplitN(l.blob, " ", 2)[0])
				removed++
				return true
			}
			kept++
			return false
		})
		newKeys -= kept
		return lines
	})
	if err != nil {
		return err
	}
	if newKeys > 0 {
		fmt.Printf("i %d newly published key(s) not on this host; run messh add <user> to review them\n", newKeys)
	}
	fmt.Println("✓ in sync")
	return nil
}

// --- keys ---

func cmdKeys(args []string) error {
	c := newClient()
	if err := c.mustAuth(); err != nil {
		return err
	}
	if len(args) > 0 && args[0] == "revoke" {
		fs := flag.NewFlagSet("keys revoke", flag.ExitOnError)
		reason := fs.String("reason", "", "why (lost, rotated, compromised)")
		pos := parse(fs, args[1:])
		if len(pos) != 1 {
			return errors.New("usage: messh keys revoke <name> [--reason R]")
		}
		var out map[string]string
		if err := c.do("POST", "/api/v1/keys/"+pos[0]+"/revoke", apitypes.RevokeRequest{Reason: *reason}, &out); err != nil {
			return err
		}
		fmt.Printf("✓ Revoked %s (%s). Hosts drop it on their next messh sync.\n", pos[0], out["fingerprint"])
		return nil
	}
	if len(args) > 0 {
		return fmt.Errorf("unknown keys subcommand %q", args[0])
	}
	var p apitypes.Profile
	if err := c.do("GET", "/api/v1/me", nil, &p); err != nil {
		return err
	}
	fmt.Printf("%s · %d active\n", p.Username, len(p.Keys))
	for _, k := range p.Keys {
		fmt.Printf("  %-10s %-12s %s  %s\n", k.Name, k.Type, k.Fingerprint, strings.Join(k.Agents, ","))
	}
	for _, r := range p.Revoked {
		fmt.Printf("  %-10s revoked %s  %s %s\n", r.Name, r.RevokedAt.Format("Jan 2 15:04"), r.Fingerprint, r.Reason)
	}
	return nil
}

// --- curl: Web Bot Auth ---

func cmdCurl(args []string) error {
	fs := flag.NewFlagSet("curl", flag.ExitOnError)
	method := fs.String("X", "", "HTTP method (default GET, or POST with -d)")
	data := fs.String("d", "", "request body")
	var headers multi
	fs.Var(&headers, "H", "extra header 'Name: value' (repeatable)")
	home, _ := os.UserHomeDir()
	keyPath := fs.String("key", filepath.Join(home, ".ssh", "id_ed25519.pub"), "ssh-ed25519 public key to sign with")
	as := fs.String("as", "", "messh identity (default: the one you logged in as)")
	verbose := fs.Bool("v", false, "print the signature headers and response headers")
	pos := parse(fs, args)
	if len(pos) != 1 {
		return errors.New("usage: messh curl [-X M] [-d BODY] [-H 'K: V'] <url>")
	}
	who := *as
	if who == "" {
		who = loadConfig().Username
	}
	if !apitypes.UsernameRe.MatchString(who) {
		return errors.New("no identity: run messh login or pass --as <user>")
	}
	if *method == "" {
		*method = "GET"
		if *data != "" {
			*method = "POST"
		}
	}
	var body io.Reader
	if *data != "" {
		body = strings.NewReader(*data)
	}
	req, err := http.NewRequest(*method, pos[0], body)
	if err != nil {
		return err
	}
	for _, h := range headers {
		k, v, ok := strings.Cut(h, ":")
		if !ok {
			return fmt.Errorf("bad header %q", h)
		}
		req.Header.Add(strings.TrimSpace(k), strings.TrimSpace(v))
	}
	req.Header.Set("User-Agent", "messh/"+version)

	key, err := signingKey(*keyPath)
	if err != nil {
		return err
	}
	client, err := messh.NewClient(who, messh.WithKey(key), messh.WithRegistry(registryURL()))
	if err != nil {
		return err
	}
	if err := client.Sign(req); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "signed as %s (keyid %s)\n", who, client.KeyID())
	if *verbose {
		for _, h := range []string{"Signature-Agent", "Signature-Input", "Signature", "Content-Digest"} {
			if v := req.Header.Get(h); v != "" {
				fmt.Fprintf(os.Stderr, "> %s: %s\n", h, v)
			}
		}
	}
	resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	fmt.Fprintf(os.Stderr, "%s %s\n", resp.Proto, resp.Status)
	if *verbose {
		for k, vs := range resp.Header {
			fmt.Fprintf(os.Stderr, "< %s: %s\n", k, strings.Join(vs, ", "))
		}
	}
	io.Copy(os.Stdout, resp.Body)
	if resp.StatusCode >= 400 {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return nil
}
