package messh_test

import (
	"encoding/hex"
	"net/http"
	"strings"
	"testing"
	"time"

	"messh.io/go/messh"
	vec "messh.io/go/messh/internal/vectors"
)

func TestClientDictionaryAgentVector(t *testing.T) {
	doc, ok := vec.Load()
	if !ok {
		t.Skip("vectors live in the messh repo (spec/vectors)")
	}
	for _, c := range doc.Sign {
		if c.Client == nil {
			continue
		}
		seed, _ := hex.DecodeString(doc.Keys[c.Key].SeedHex)
		cl, err := messh.NewClient(c.Client.Identity, messh.WithKey(messh.KeySeed(seed)), messh.WithRegistry(c.Client.Registry),
			messh.WithClock(func() time.Time { return time.Unix(c.Client.Created, 0) }), messh.WithNonce(func() string { return c.Client.Nonce }),
			messh.WithAgentDictionary())
		if err != nil {
			t.Fatal(err)
		}
		req, _ := http.NewRequest(c.Message.Method, c.Message.URL, nil)
		if err := cl.Sign(req); err != nil {
			t.Fatal(err)
		}
		for _, name := range []string{"Signature-Agent", "Signature-Input", "Signature"} {
			if got := req.Header.Get(name); got != c.Headers[name] {
				t.Errorf("%s: %s\n%s\nwant\n%s", c.Name, name, got, c.Headers[name])
			}
		}
	}
}

func TestDirectoryResponseVector(t *testing.T) {
	doc, ok := vec.Load()
	if !ok {
		t.Skip("vectors live in the messh repo (spec/vectors)")
	}
	d := doc.Directory.Sign
	var keys []messh.KeySource
	for _, name := range d.Keys {
		seed, _ := hex.DecodeString(doc.Keys[name].SeedHex)
		keys = append(keys, messh.KeySeed(seed))
	}
	body, h, err := messh.DirectoryResponse(d.Authority, keys, time.Unix(d.Created, 0), time.Duration(d.ExpiresIn)*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != d.Body {
		t.Errorf("body\n%s\nwant\n%s", body, d.Body)
	}
	for name, want := range d.Headers {
		if got := strings.Join(h.Values(name), ", "); got != want {
			t.Errorf("%s\n%s\nwant\n%s", name, got, want)
		}
	}
}
