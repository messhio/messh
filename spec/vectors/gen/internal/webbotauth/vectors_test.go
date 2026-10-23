package webbotauth

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"net/http/httptest"
)

// TestVectors checks the published conformance vectors (spec/vectors, or
// MESSH_VECTORS) against this reference verifier.
func TestVectors(t *testing.T) {
	path := os.Getenv("MESSH_VECTORS")
	if path == "" {
		path = "../../../web-bot-auth.json"
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Verify []struct {
			Name, Method, URL, Body, Expect string
			Headers                         map[string]string
			Now                             int64
			Keys                            []JWK `json:"directory_keys"`
		}
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	for _, c := range doc.Verify {
		r := httptest.NewRequest(c.Method, c.URL, strings.NewReader(c.Body))
		for k, v := range c.Headers {
			r.Header.Set(k, v)
		}
		keys := c.Keys
		v := &Verifier{
			Resolve: func(context.Context, string) (*Directory, error) { return &Directory{Keys: keys}, nil },
			Nonces:  NewNonceStore(),
			Now:     func() time.Time { return time.Unix(c.Now, 0) },
		}
		_, err := v.Verify(r)
		got := "ok"
		if err != nil {
			got = err.(*Error).Code
		}
		if got != c.Expect {
			t.Errorf("%s: got %s, want %s (%v)", c.Name, got, c.Expect, err)
		}
	}
}
