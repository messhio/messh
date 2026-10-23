package messh_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"messh.io/go/messh"
)

type jwk struct {
	Kid         string `json:"kid"`
	Fingerprint string `json:"messh_fingerprint"`
}

func vectorKey(t *testing.T) (path string, key jwk, raw json.RawMessage) {
	b, err := os.ReadFile("../../spec/vectors/web-bot-auth.json")
	if os.IsNotExist(err) {
		t.Skip("conformance vectors live in the messh monorepo (spec/vectors)")
	}
	var doc struct {
		Key struct {
			Files struct{ Openssh string }
			JWK   json.RawMessage `json:"jwk"`
		}
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	json.Unmarshal(doc.Key.JWK, &key)
	return filepath.Join("../../spec/vectors", doc.Key.Files.Openssh), key, doc.Key.JWK
}

func code(err error) string {
	var e *messh.Error
	if errors.As(err, &e) {
		return e.Code
	}
	if err != nil {
		return err.Error()
	}
	return "ok"
}

func TestFingerprint(t *testing.T) {
	path, key, _ := vectorKey(t)
	c, err := messh.NewClient("mukul", messh.WithKey(messh.KeyFile(path)))
	if err != nil {
		t.Fatal(err)
	}
	if c.Fingerprint() != key.Fingerprint {
		t.Fatalf("fingerprint %s, want %s", c.Fingerprint(), key.Fingerprint)
	}
}

func TestNewClientFromEnv(t *testing.T) {
	path, key, _ := vectorKey(t)
	t.Setenv("MESSH_IDENTITY", "mukul")
	t.Setenv("MESSH_KEY", "")
	t.Setenv("MESSH_KEY_FILE", path)
	t.Setenv("MESSH_REGISTRY", "https://registry.example/")
	c, err := messh.NewClientFromEnv()
	if err != nil || c.KeyID() != key.Kid || c.Agent() != "https://registry.example/mukul" {
		t.Fatalf("from env: %v %v", c, err)
	}
	t.Setenv("MESSH_IDENTITY", "")
	if _, err := messh.NewClientFromEnv(); code(err) != "invalid_identity" || !strings.Contains(err.Error(), "MESSH_IDENTITY") {
		t.Fatalf("no identity: %v", err)
	}
}

func TestKeyFileHomeAndMissing(t *testing.T) {
	path, key, _ := vectorKey(t)
	home := t.TempDir()
	b, _ := os.ReadFile(path)
	os.WriteFile(filepath.Join(home, "id"), b, 0o600)
	t.Setenv("HOME", home)
	c, err := messh.NewClient("mukul", messh.WithKey(messh.KeyFile("~/id")))
	if err != nil || c.KeyID() != key.Kid {
		t.Fatalf("~/ path: %v", err)
	}
	if _, err := messh.NewClient("mukul", messh.WithKey(messh.KeyFile("~/nope"))); !strings.Contains(err.Error(), "ssh-keygen -t ed25519") {
		t.Fatalf("missing key hint: %v", err)
	}
}

func TestWhoAmI(t *testing.T) {
	path, key, raw := vectorKey(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch strings.Split(r.URL.Path, "/")[1] {
		case "mukul":
			w.Write([]byte(`{"keys":[` + string(raw) + `]}`))
		case "empty":
			w.Write([]byte(`{"keys":[]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	as := func(id string) *messh.Client {
		c, err := messh.NewClient(id, messh.WithKey(messh.KeyFile(path)), messh.WithRegistry(srv.URL))
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	got, err := as("mukul").WhoAmI(context.Background())
	want := &messh.PublishedKey{Identity: "mukul", KeyName: "sdk-test", KeyID: key.Kid, Fingerprint: key.Fingerprint, AgentURL: srv.URL + "/mukul"}
	if err != nil || *got != *want {
		t.Fatalf("whoami: %+v %v", got, err)
	}
	if _, err := as("nobody").WhoAmI(context.Background()); code(err) != "not_published" || !strings.Contains(err.Error(), "no user nobody") {
		t.Fatalf("unknown user: %v", err)
	}
	if _, err := as("empty").WhoAmI(context.Background()); code(err) != "not_published" || !strings.Contains(err.Error(), key.Fingerprint) {
		t.Fatalf("unpublished key: %v", err)
	}
	srv.Close()
	if _, err := as("mukul").WhoAmI(context.Background()); code(err) != "registry_unreachable" {
		t.Fatalf("unreachable: %v", err)
	}
}

// A real ssh-agent holding the conformance key signs byte-identically to the file.
func TestSSHAgent(t *testing.T) {
	agentBin, err := exec.LookPath("ssh-agent")
	if err != nil {
		t.Skip("ssh-agent not installed")
	}
	path, key, _ := vectorKey(t)
	dir := t.TempDir()
	sock, keyCopy := filepath.Join(dir, "agent.sock"), filepath.Join(dir, "id")
	b, _ := os.ReadFile(path)
	os.WriteFile(keyCopy, b, 0o600)
	agent := exec.Command(agentBin, "-D", "-a", sock)
	if err := agent.Start(); err != nil {
		t.Fatal(err)
	}
	defer agent.Process.Kill()
	for i := 0; i < 50; i++ {
		if _, err := os.Stat(sock); err == nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	add := exec.Command("ssh-add", keyCopy)
	add.Env = append(os.Environ(), "SSH_AUTH_SOCK="+sock)
	if out, err := add.CombinedOutput(); err != nil {
		t.Fatalf("ssh-add: %v %s", err, out)
	}
	t.Setenv("SSH_AUTH_SOCK", sock)

	clock := messh.WithClock(func() time.Time { return time.Unix(1760882531, 0) })
	nonce := messh.WithNonce(func() string { return "b3k2pUe8Qz1" })
	sign := func(k messh.KeySource) string {
		c, err := messh.NewClient("mukul", messh.WithKey(k), clock, nonce)
		if err != nil {
			t.Fatal(err)
		}
		req, _ := http.NewRequest("POST", "https://api.acme.dev/deployments", strings.NewReader(`{"env":"staging"}`))
		if err := c.Sign(req); err != nil {
			t.Fatal(err)
		}
		return req.Header.Get("Signature")
	}
	if a, f := sign(messh.SSHAgent("")), sign(messh.KeyFile(path)); a != f {
		t.Fatalf("agent signature %s, file signature %s", a, f)
	}
	if _, err := messh.NewClient("mukul", messh.WithKey(messh.SSHAgent("SHA256:nope"))); !strings.Contains(err.Error(), key.Fingerprint) {
		t.Fatalf("unknown fingerprint should list the agent's keys: %v", err)
	}
}
