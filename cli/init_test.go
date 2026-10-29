package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"golang.org/x/crypto/ssh"

	"messh.io/go/messh/verify"

	"github.com/messhio/messh/cli/internal/apitypes"
)

func TestFreeKeyName(t *testing.T) {
	long := strings.Repeat("a", 32)
	keys := []apitypes.Key{{Name: "laptop"}, {Name: "laptop-2"}, {Name: long}}
	for base, want := range map[string]string{"desk": "desk", "laptop": "laptop-3", long: long[:30] + "-2"} {
		if got := freeKeyName(base, keys); got != want {
			t.Errorf("freeKeyName(%q) = %q, want %q", base, got, want)
		}
	}
}

// fakeRegistry serves what messh init uses: /api/v1/me, publish with a
// challenge, and a signature check that runs the Go SDK's verifier against
// the keys published so far.
type fakeRegistry struct {
	*httptest.Server
	mu      sync.Mutex
	keys    []apitypes.Key
	pending string // public key awaiting its challenge
	checks  int    // signed requests verified
}

func newFakeRegistry(t *testing.T) *fakeRegistry {
	f := &fakeRegistry{}
	mux := http.NewServeMux()
	f.Server = httptest.NewServer(mux)
	t.Cleanup(f.Close)
	authed := func(h http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Authorization") != "Bearer tok" {
				w.WriteHeader(http.StatusUnauthorized)
				json.NewEncoder(w).Encode(apitypes.Error{Error: "unauthorized"})
				return
			}
			f.mu.Lock()
			defer f.mu.Unlock()
			h(w, r)
		}
	}
	mux.HandleFunc("GET /api/v1/me", authed(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(apitypes.Profile{Username: "mukul", Keys: f.keys})
	}))
	mux.HandleFunc("POST /api/v1/keys/challenge", authed(func(w http.ResponseWriter, r *http.Request) {
		var req apitypes.ChallengeRequest
		json.NewDecoder(r.Body).Decode(&req)
		f.pending = req.PublicKey
		json.NewEncoder(w).Encode(apitypes.Challenge{ID: "ch1", Namespace: "messh-publish", Message: "prove it"})
	}))
	mux.HandleFunc("POST /api/v1/keys", authed(func(w http.ResponseWriter, r *http.Request) {
		var req apitypes.PublishRequest
		json.NewDecoder(r.Body).Decode(&req)
		pk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(f.pending))
		if err != nil || !strings.HasPrefix(req.Signature, "-----BEGIN SSH SIGNATURE-----") {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(apitypes.Error{Error: "possession_failed"})
			return
		}
		k := apitypes.Key{Name: req.Name, Type: pk.Type(), PublicKey: f.pending, Fingerprint: ssh.FingerprintSHA256(pk), Status: "active", Possession: true}
		f.keys = append(f.keys, k)
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(k)
	}))
	v, err := verify.New(verify.Trust("*"), verify.Registry(f.URL, ""), verify.DirectoryFunc(f.directory))
	if err != nil {
		t.Fatal(err)
	}
	mux.HandleFunc(echoPath, func(w http.ResponseWriter, r *http.Request) {
		a, err := v.Verify(r)
		var ve *verify.Error
		if errors.As(err, &ve) {
			w.WriteHeader(ve.Status)
			json.NewEncoder(w).Encode(map[string]any{"verified": false, "error": ve.Code, "message": ve.Message})
			return
		}
		f.mu.Lock()
		f.checks++
		f.mu.Unlock()
		json.NewEncoder(w).Encode(map[string]any{"verified": true, "message": "signed by " + a.Identity + " with key " + a.KeyName})
	})
	return f
}

// directory is the published keys as a Web Bot Auth key directory.
func (f *fakeRegistry) directory(_ context.Context, _, identity string) (*verify.Directory, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if identity != "mukul" {
		return nil, nil
	}
	jwks := []map[string]string{}
	for _, k := range f.keys {
		pk, _, _, _, _ := ssh.ParseAuthorizedKey([]byte(k.PublicKey))
		x := base64.RawURLEncoding.EncodeToString(pk.(ssh.CryptoPublicKey).CryptoPublicKey().(ed25519.PublicKey))
		kid := sha256.Sum256([]byte(`{"crv":"Ed25519","kty":"OKP","x":"` + x + `"}`))
		jwks = append(jwks, map[string]string{"kty": "OKP", "crv": "Ed25519", "x": x, "kid": base64.RawURLEncoding.EncodeToString(kid[:]), "messh_name": k.Name})
	}
	b, _ := json.Marshal(map[string]any{"keys": jwks})
	var d verify.Directory
	return &d, json.Unmarshal(b, &d)
}

func (f *fakeRegistry) state() (keys []apitypes.Key, checks int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.keys, f.checks
}

// TestInit: from a signed-in CLI with no key, messh init creates one, proves
// possession with ssh-keygen, publishes it and passes the signature check.
// Running it again only repeats the check.
func TestInit(t *testing.T) {
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		t.Skip("needs ssh-keygen")
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, "config"))
	t.Setenv("MESSH_REGISTRY", "")
	t.Setenv("SSH_AUTH_SOCK", "")
	f := newFakeRegistry(t)
	if err := saveSession(config{Registry: f.URL, Username: "mukul"}, "tok"); err != nil {
		t.Fatal(err)
	}

	if err := cmdInit([]string{"--yes", "--name", "laptop"}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(home, ".ssh", "id_ed25519")); err != nil {
		t.Fatalf("no key created: %v", err)
	}
	if keys, checks := f.state(); len(keys) != 1 || keys[0].Name != "laptop" || checks != 1 {
		t.Fatalf("after init: keys %v, checks %d", keys, checks)
	}

	if err := cmdInit([]string{"--yes"}); err != nil {
		t.Fatal(err)
	}
	if keys, checks := f.state(); len(keys) != 1 || checks != 2 {
		t.Fatalf("after second init: keys %v, checks %d", keys, checks)
	}
}

// TestInitRefusesOtherKeyTypes: signed requests need ssh-ed25519.
func TestInitRefusesOtherKeyTypes(t *testing.T) {
	home := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, "config"))
	t.Setenv("MESSH_REGISTRY", "")
	f := newFakeRegistry(t)
	if err := saveSession(config{Registry: f.URL, Username: "mukul"}, "tok"); err != nil {
		t.Fatal(err)
	}
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pk, _ := ssh.NewPublicKey(&priv.PublicKey)
	pub := filepath.Join(home, "id_ecdsa.pub")
	if err := os.WriteFile(pub, ssh.MarshalAuthorizedKey(pk), 0o644); err != nil {
		t.Fatal(err)
	}
	err := cmdInit([]string{"--yes", "--key", pub})
	if err == nil || !strings.Contains(err.Error(), "ssh-ed25519") {
		t.Fatalf("got %v", err)
	}
	if keys, _ := f.state(); len(keys) != 0 {
		t.Fatalf("published %v", keys)
	}
}
