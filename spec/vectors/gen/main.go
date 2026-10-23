// Command gen writes the shared Web Bot Auth conformance vectors that every
// messh SDK must reproduce: go run . <out-dir>. `make vectors` checks that
// spec/vectors is exactly what it writes.
package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/messhio/messh/spec/vectors/gen/internal/webbotauth"
)

type signer struct{ k ed25519.PrivateKey }

func (s signer) Public() ed25519.PublicKey     { return s.k.Public().(ed25519.PublicKey) }
func (s signer) Sign(d []byte) ([]byte, error) { return ed25519.Sign(s.k, d), nil }

type signCase struct {
	Name      string            `json:"name"`
	Method    string            `json:"method"`
	URL       string            `json:"url"`
	Body      string            `json:"body,omitempty"`
	Created   int64             `json:"created"`
	Nonce     string            `json:"nonce"`
	ExpiresIn int               `json:"expires_in"`
	Headers   map[string]string `json:"expected_headers"`
	Base      string            `json:"expected_signature_base"`
}

type verifyCase struct {
	Name    string            `json:"name"`
	Method  string            `json:"method"`
	URL     string            `json:"url"`
	Headers map[string]string `json:"headers"`
	Body    string            `json:"body,omitempty"`
	Now     int64             `json:"now"`
	Keys    []webbotauth.JWK  `json:"directory_keys"`
	Expect  string            `json:"expect"` // "ok" or an error code
}

const agent = "https://registry.example/mukul"

// keySeed derives the conformance key: sha256(keySeed) is its Ed25519 seed.
const keySeed = "messh web-bot-auth test vector key 1"

func main() {
	out := os.Args[1]
	os.MkdirAll(out, 0o755)
	seed := sha256.Sum256([]byte(keySeed))
	priv := ed25519.NewKeyFromSeed(seed[:])
	s := signer{priv}
	pub := s.Public()

	// Key fixtures in every format the SDKs load.
	block, _ := ssh.MarshalPrivateKey(priv, "messh-test-vector")
	must(os.WriteFile(filepath.Join(out, "test_ed25519"), pem.EncodeToMemory(block), 0o600))
	sp, _ := ssh.NewPublicKey(pub)
	must(os.WriteFile(filepath.Join(out, "test_ed25519.pub"), []byte(strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sp)))+" messh-test-vector\n"), 0o644))
	der, _ := x509.MarshalPKCS8PrivateKey(priv)
	must(os.WriteFile(filepath.Join(out, "test_ed25519.pkcs8.pem"), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600))

	jwk := webbotauth.NewJWK(pub, "sdk-test", ssh.FingerprintSHA256(sp))
	_, other, _ := ed25519.GenerateKey(zero{})
	otherJWK := webbotauth.NewJWK(other.Public().(ed25519.PublicKey), "other", "")

	var signs []signCase
	var verifies []verifyCase
	add := func(name, method, url, body string, created int64, nonce string) signCase {
		var rb io.Reader
		if body != "" {
			rb = strings.NewReader(body)
		}
		req, _ := http.NewRequest(method, url, rb)
		must(webbotauth.Sign(req, s, agent, time.Unix(created, 0), nonce))
		h := map[string]string{}
		for _, k := range []string{"Signature-Agent", "Signature-Input", "Signature", "Content-Digest"} {
			if v := req.Header.Get(k); v != "" {
				h[k] = v
			}
		}
		srv, _ := http.NewRequest(method, url, strings.NewReader(body))
		for k, v := range h {
			srv.Header.Set(k, v)
		}
		base, err := webbotauth.SignatureBaseOf(srv)
		must(err)
		c := signCase{name, method, url, body, created, nonce, 60, h, base}
		signs = append(signs, c)
		return c
	}
	get := add("get", "GET", "https://app.example/api/hello", "", 1760000000, "nonce-get-1")
	q := add("get-query", "GET", "https://app.example/api/items?limit=10&sort=asc", "", 1760000000, "nonce-query-1")
	post := add("post-json", "POST", "https://app.example/api/deploy", `{"env":"staging"}`, 1760000000, "nonce-post-1")
	add("port-authority", "GET", "http://localhost:8090/api/hello", "", 1760000000, "nonce-port-1")

	vc := func(name string, c signCase, mut func(*verifyCase), expect string) {
		h := map[string]string{}
		for k, v := range c.Headers {
			h[k] = v
		}
		v := verifyCase{name, c.Method, c.URL, h, c.Body, c.Created + 5, []webbotauth.JWK{jwk}, expect}
		if mut != nil {
			mut(&v)
		}
		verifies = append(verifies, v)
	}
	vc("ok-get", get, nil, "ok")
	vc("ok-query", q, nil, "ok")
	vc("ok-post", post, nil, "ok")
	vc("missing-signature", get, func(v *verifyCase) { v.Headers = map[string]string{} }, "missing_signature")
	vc("tampered-path", get, func(v *verifyCase) { v.URL = "https://app.example/api/admin" }, "bad_signature")
	vc("tampered-method", get, func(v *verifyCase) { v.Method = "DELETE" }, "bad_signature")
	vc("tampered-authority", get, func(v *verifyCase) { v.URL = "https://evil.example/api/hello" }, "bad_signature")
	vc("tampered-agent", get, func(v *verifyCase) { v.Headers["Signature-Agent"] = `"https://registry.example/bob"` }, "bad_signature")
	vc("tampered-body", post, func(v *verifyCase) { v.Body = `{"env":"prod"}` }, "digest_mismatch")
	vc("expired", get, func(v *verifyCase) { v.Now = get.Created + 600 }, "clock_skew")
	vc("future", get, func(v *verifyCase) { v.Now = get.Created - 600 }, "clock_skew")
	vc("unknown-key", get, func(v *verifyCase) { v.Keys = []webbotauth.JWK{otherJWK} }, "unknown_key")
	vc("wrong-tag", get, func(v *verifyCase) {
		v.Headers["Signature-Input"] = strings.Replace(v.Headers["Signature-Input"], `tag="web-bot-auth"`, `tag="other"`, 1)
	}, "bad_signature")

	doc := map[string]any{
		"description": "messh Web Bot Auth conformance vectors (RFC 9421, Ed25519, tag=web-bot-auth). Generated by spec/vectors/gen from the reference verifier.",
		"agent":       agent,
		"key": map[string]any{
			"seed_hex": hex.EncodeToString(seed[:]), "jwk": jwk,
			"files": map[string]string{"openssh": "test_ed25519", "pkcs8": "test_ed25519.pkcs8.pem", "public": "test_ed25519.pub"},
		},
		"max_skew": 60,
		"sign":     signs,
		"verify":   verifies,
		"notes":    "Verify cases: authority comes from the URL host; directory_keys is the agent's key directory. A second verify of any ok case with the same nonce must fail with nonce_replayed.",
	}
	b, _ := json.MarshalIndent(doc, "", "  ")
	must(os.WriteFile(filepath.Join(out, "web-bot-auth.json"), append(b, '\n'), 0o644))
}

type zero struct{}

func (zero) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 7
	}
	return len(p), nil
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}
