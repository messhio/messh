package messh_test

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"messh.io/go/messh"
)

const vectorsDir = "../../spec/vectors"

type vectors struct {
	Agent string `json:"agent"`
	Key   struct {
		SeedHex string            `json:"seed_hex"`
		JWK     map[string]string `json:"jwk"`
		Files   map[string]string `json:"files"`
	} `json:"key"`
	Sign []struct {
		Name, Method, URL, Body, Nonce string
		Created                        int64
		Headers                        map[string]string `json:"expected_headers"`
	} `json:"sign"`
}

func load(t *testing.T) vectors {
	b, err := os.ReadFile(filepath.Join(vectorsDir, "web-bot-auth.json"))
	if os.IsNotExist(err) {
		t.Skip("conformance vectors live in the messh monorepo (spec/vectors)")
	}
	if err != nil {
		t.Fatal(err)
	}
	var v vectors
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func TestSignVectors(t *testing.T) {
	v := load(t)
	for _, c := range v.Sign {
		cl, err := messh.NewClient("mukul",
			messh.WithKey(messh.KeyFile(filepath.Join(vectorsDir, v.Key.Files["openssh"]))),
			messh.WithRegistry("https://registry.example"),
			messh.WithClock(func() time.Time { return time.Unix(c.Created, 0) }),
			messh.WithNonce(func() string { return c.Nonce }))
		if err != nil {
			t.Fatal(err)
		}
		var body *strings.Reader
		req, _ := http.NewRequest(c.Method, c.URL, nil)
		if c.Body != "" {
			body = strings.NewReader(c.Body)
			req, _ = http.NewRequest(c.Method, c.URL, body)
		}
		if err := cl.Sign(req); err != nil {
			t.Fatal(err)
		}
		for k, want := range c.Headers {
			if got := req.Header.Get(k); got != want {
				t.Errorf("%s %s:\n got %s\nwant %s", c.Name, k, got, want)
			}
		}
	}
}

func TestKeySources(t *testing.T) {
	v := load(t)
	want := v.Key.JWK["kid"]
	seed, _ := hex.DecodeString(v.Key.SeedHex)
	pkcs8, _ := os.ReadFile(filepath.Join(vectorsDir, v.Key.Files["pkcs8"]))
	t.Setenv("MESSH_TEST_KEY", base64.StdEncoding.EncodeToString(pkcs8))
	for name, ks := range map[string]messh.KeySource{
		"openssh": messh.KeyFile(filepath.Join(vectorsDir, v.Key.Files["openssh"])),
		"pkcs8":   messh.KeyFile(filepath.Join(vectorsDir, v.Key.Files["pkcs8"])),
		"env":     messh.KeyEnv("MESSH_TEST_KEY"),
		"seed":    messh.KeySeed(seed),
	} {
		c, err := messh.NewClient("mukul", messh.WithKey(ks))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if c.KeyID() != want {
			t.Errorf("%s: keyid %s, want %s", name, c.KeyID(), want)
		}
	}
	if _, err := messh.NewClient("mukul", messh.WithKey(messh.KeyFile(filepath.Join(vectorsDir, v.Key.Files["public"])))); err == nil {
		t.Error("public key accepted as a signing key")
	}
	if _, err := messh.NewClient("Not A User", messh.WithKey(messh.KeySeed(seed))); err == nil {
		t.Error("bad identity accepted")
	}
}
