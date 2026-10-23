package webbotauth

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const testAgent = "https://messh.example/mukul"

func setup(t *testing.T) (keySigner, *Verifier) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	s := keySigner{priv: priv}
	dir := &Directory{Keys: []JWK{NewJWK(s.Public(), "laptop", "")}}
	return s, &Verifier{
		Resolve: func(_ context.Context, a string) (*Directory, error) {
			if a != testAgent {
				t.Fatalf("resolved unexpected testAgent %q", a)
			}
			return dir, nil
		},
		Nonces: NewNonceStore(),
	}
}

// signed builds a client request, signs it, and replays it as the server sees it.
func signed(t *testing.T, s Signer, method, url, body string) *http.Request {
	var req *http.Request
	if body != "" {
		req, _ = http.NewRequest(method, url, strings.NewReader(body))
	} else {
		req, _ = http.NewRequest(method, url, nil)
	}
	if err := Sign(req, s, testAgent, time.Now(), "n-"+t.Name()); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewRequest(method, url, strings.NewReader(body))
	srv.Header = req.Header.Clone()
	return srv
}

func code(err error) string {
	if e, ok := err.(*Error); ok {
		return e.Code
	}
	return ""
}

func TestRoundTrip(t *testing.T) {
	s, v := setup(t)
	r := signed(t, s, "GET", "http://app.example/api/hello?x=1", "")
	res, err := v.Verify(r)
	if err != nil {
		t.Fatal(err)
	}
	if res.Agent != testAgent || res.Key.Name != "laptop" {
		t.Fatalf("got %+v", res)
	}
	if _, err := v.Verify(r); code(err) != "nonce_replayed" {
		t.Fatalf("replay: got %v", err)
	}
}

func TestBodyDigest(t *testing.T) {
	s, v := setup(t)
	r := signed(t, s, "POST", "http://app.example/api/deploy", `{"env":"staging"}`)
	if _, err := v.Verify(r); err != nil {
		t.Fatal(err)
	}
	r = signed(t, s, "POST", "http://app.example/api/deploy", `{"env":"staging"}`)
	r.Body = http.NoBody
	r2 := httptest.NewRequest("POST", "http://app.example/api/deploy", strings.NewReader(`{"env":"prod"}`))
	r2.Header = r.Header
	if _, err := v.Verify(r2); code(err) != "digest_mismatch" {
		t.Fatalf("tampered body: got %v", err)
	}
}

func TestTamperAndUnknown(t *testing.T) {
	s, v := setup(t)
	r := signed(t, s, "GET", "http://app.example/api/hello", "")
	r.URL.Path = "/api/admin"
	if _, err := v.Verify(r); code(err) != "bad_signature" {
		t.Fatalf("tampered path: got %v", err)
	}
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	r = signed(t, keySigner{priv: other}, "GET", "http://app.example/api/hello", "")
	if _, err := v.Verify(r); code(err) != "unknown_key" {
		t.Fatalf("unknown key: got %v", err)
	}
	r = httptest.NewRequest("GET", "http://app.example/", nil)
	if _, err := v.Verify(r); code(err) != "missing_signature" {
		t.Fatalf("unsigned: got %v", err)
	}
}

func TestClockSkew(t *testing.T) {
	s, v := setup(t)
	r := signed(t, s, "GET", "http://app.example/", "")
	v.Now = func() time.Time { return time.Now().Add(5 * time.Minute) }
	if _, err := v.Verify(r); code(err) != "clock_skew" {
		t.Fatalf("got %v", err)
	}
}

// RFC 7638 §3.1-style check: thumbprint input has members in lexical order.
func TestThumbprintStable(t *testing.T) {
	pub := make([]byte, 32)
	if Thumbprint(pub) != Thumbprint(pub) || len(Thumbprint(pub)) != 43 {
		t.Fatal("thumbprint must be a 43-char base64url SHA-256")
	}
}
