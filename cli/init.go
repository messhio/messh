package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"messh.io/go/messh"

	"github.com/messhio/messh/cli/internal/apitypes"
)

// echoPath is the registry's signature check: it verifies a signed request
// the way an API would and says who signed it.
const echoPath = "/api/v1/echo"

// cmdInit takes a new user from nothing to a working identity: sign in, an
// ssh-ed25519 key (created if there is none), published with proof of
// possession, then one signed request the registry verifies. Each step is
// skipped when it's already done, so running it again is safe.
func cmdInit(args []string) error {
	fs := flag.NewFlagSet("init", flag.ExitOnError)
	home, _ := os.UserHomeDir()
	keyPath := fs.String("key", filepath.Join(home, ".ssh", "id_ed25519.pub"), "ssh-ed25519 public key; created if missing")
	name := fs.String("name", "", "label for this key (default: this machine's name)")
	var agents multi
	fs.Var(&agents, "agent", "agent using this key (repeatable)")
	yes := fs.Bool("yes", false, "don't prompt; a missing key is created without a passphrase")
	parse(fs, args)

	c := newClient()
	me, err := c.me()
	var ae *apiError
	if errors.As(err, &ae) && ae.Status == http.StatusUnauthorized {
		if _, err := login(c); err != nil {
			return err
		}
		me, err = c.me()
	} else if err == nil {
		fmt.Printf("✓ Logged in as %s\n", me.Username)
	}
	if err != nil {
		return fmt.Errorf("registry %s: %w", c.base, err)
	}

	if _, err := os.Stat(*keyPath); errors.Is(err, os.ErrNotExist) {
		if err := createKey(*keyPath, me.Username+"@"+defaultKeyName(), *yes); err != nil {
			return err
		}
	}
	k, err := readPublicKey(*keyPath)
	if err != nil {
		return err
	}
	if k.Type != "ssh-ed25519" {
		return fmt.Errorf("%s is %s; signed requests need an ssh-ed25519 key. Pass --key with one, or use messh publish for SSH only", *keyPath, k.Type)
	}
	var key *apitypes.Key
	for i := range me.Keys {
		if me.Keys[i].Fingerprint == k.Fingerprint {
			key = &me.Keys[i]
		}
	}
	if key != nil {
		fmt.Printf("✓ %s is published as %s\n", *keyPath, key.Name)
	} else {
		if *name == "" {
			*name = freeKeyName(defaultKeyName(), me.Keys)
		}
		if key, err = publishKey(c, *keyPath, k, *name, agents); err != nil {
			return err
		}
		fmt.Printf("✓ Published %s %s as %s: %s/%s\n", key.Type, key.Fingerprint, key.Name, c.base, me.Username)
	}

	if err := checkSigned(c.base, me.Username, *keyPath); err != nil {
		return err
	}
	fmt.Printf("\nAgents and scripts sign as %s with:\n", me.Username)
	fmt.Printf("  export MESSH_IDENTITY=%s\n", me.Username)
	fmt.Printf("  export MESSH_KEY_FILE=%s\n", strings.TrimSuffix(*keyPath, ".pub"))
	if c.base != defaultRegistry {
		fmt.Printf("  export MESSH_REGISTRY=%s\n", c.base)
	}
	fmt.Printf("Try it:  messh curl %s%s\n", c.base, echoPath)
	fmt.Printf("Servers: run messh add %s on a server to let this key in\n", me.Username)
	return nil
}

// createKey makes an ssh-ed25519 key pair with ssh-keygen; pubPath names the
// public half. Without --yes it asks first, and ssh-keygen asks for a passphrase.
func createKey(pubPath, comment string, yes bool) error {
	priv, ok := strings.CutSuffix(pubPath, ".pub")
	if !ok {
		return fmt.Errorf("%s doesn't exist; pass the .pub path of a key, or of one to create", pubPath)
	}
	if _, err := os.Stat(priv); err == nil {
		return fmt.Errorf("%s exists but %s doesn't; recreate it with ssh-keygen -y -f %s > %s", priv, pubPath, priv, pubPath)
	}
	if !yes {
		if a := ask(fmt.Sprintf("No key at %s. Create an ssh-ed25519 key there? [Y/n] ", pubPath)); a != "" && a != "y" && a != "yes" {
			return errors.New("no key to publish; pass --key with one")
		}
	}
	if err := os.MkdirAll(filepath.Dir(priv), 0o700); err != nil {
		return err
	}
	args := []string{"-q", "-t", "ed25519", "-C", comment, "-f", priv}
	if yes {
		args = append(args, "-N", "")
	}
	cmd := exec.Command("ssh-keygen", args...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("ssh-keygen failed: %w", err)
	}
	fmt.Printf("✓ Created %s\n", priv)
	return nil
}

// freeKeyName is base, or base-2, base-3… when an active key already has the name.
func freeKeyName(base string, keys []apitypes.Key) string {
	taken := map[string]bool{}
	for _, k := range keys {
		taken[k.Name] = true
	}
	name := base
	for i := 2; taken[name]; i++ {
		suffix := fmt.Sprintf("-%d", i)
		name = base[:min(len(base), 32-len(suffix))] + suffix
	}
	return name
}

// checkSigned signs one request to the registry's signature check, the same
// check an API with a messh verifier makes.
func checkSigned(registry, identity, pubPath string) error {
	key, err := signingKey(pubPath)
	if err != nil {
		return err
	}
	sc, err := messh.NewClient(identity, messh.WithKey(key), messh.WithRegistry(registry))
	if err != nil {
		if strings.Contains(err.Error(), "passphrase") {
			priv := strings.TrimSuffix(pubPath, ".pub")
			return fmt.Errorf("%s has a passphrase: run ssh-add %s so messh can sign with it, then messh init again", priv, priv)
		}
		return err
	}
	resp, err := sc.Get(registry + echoPath)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		fmt.Printf("i %s can't check signatures yet; skipped the test request\n", registry)
		return nil
	}
	var out struct {
		Verified bool   `json:"verified"`
		Message  string `json:"message"`
		Error    string `json:"error"`
		Hint     string `json:"hint"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return fmt.Errorf("signed request check: HTTP %d", resp.StatusCode)
	}
	if !out.Verified {
		msg := fmt.Sprintf("signed request check failed: %s: %s", out.Error, out.Message)
		if out.Hint != "" {
			msg += " (" + out.Hint + ")"
		}
		return errors.New(msg)
	}
	fmt.Printf("✓ Signed request verified by %s: %s\n", registry, out.Message)
	return nil
}
