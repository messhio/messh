package httpsig_test

import (
	"crypto/ed25519"
	"errors"
	"net/http"
	"testing"
	"time"

	"messh.io/go/messh/httpsig"
	"messh.io/go/messh/internal/vectors"
)

func load(t *testing.T) *vectors.Doc {
	doc, ok := vectors.Load()
	if !ok {
		t.Skip("vectors live in the messh repo (spec/vectors)")
	}
	return doc
}

func TestComponentVectors(t *testing.T) {
	doc := load(t)
	for _, c := range doc.Components {
		msg := doc.Messages[c.Message]
		id, v, err := httpsig.Component(msg.Build(), c.Component, doc.FieldTypes)
		switch {
		case c.Error && err == nil:
			t.Errorf("%s: got %s: %q, want an error", c.Name, id, v)
		case !c.Error && err != nil:
			t.Errorf("%s: %v", c.Name, err)
		case !c.Error && (id != c.Identifier || v != c.Value):
			t.Errorf("%s: got %s: %q, want %s: %q", c.Name, id, v, c.Identifier, c.Value)
		}
	}
}

func TestSignVectors(t *testing.T) {
	doc := load(t)
	for _, c := range doc.Sign {
		o := httpsig.SignOptions{Label: c.Label, Components: c.Components, KeyID: c.Params.KeyID, Alg: c.Params.Alg,
			Nonce: c.Params.Nonce, Tag: c.Params.Tag, FieldTypes: doc.FieldTypes}
		if c.Params.Created != 0 {
			o.Created = time.Unix(c.Params.Created, 0)
		}
		if c.Params.Expires != 0 {
			o.Expires = time.Unix(c.Params.Expires, 0)
		}
		s, err := httpsig.Sign(c.Message.Build(), vectors.Signer{K: doc.Keys[c.Key].Private()}, o)
		if err != nil {
			t.Errorf("%s: %v", c.Name, err)
			continue
		}
		if s.Base != c.Base {
			t.Errorf("%s: base\n%s\nwant\n%s", c.Name, s.Base, c.Base)
		}
		h := http.Header{}
		s.AddTo(h)
		for _, name := range []string{"Signature-Input", "Signature"} {
			if h.Get(name) != c.Headers[name] {
				t.Errorf("%s: %s\n%s\nwant\n%s", c.Name, name, h.Get(name), c.Headers[name])
			}
		}
	}
}

func TestVerifyVectors(t *testing.T) {
	doc := load(t)
	for _, c := range doc.Verify {
		keys := func(id string) (ed25519.PublicKey, error) {
			name, ok := c.Keys[id]
			if !ok {
				return nil, errors.New("unknown key")
			}
			return httpsig.DecodeKey(doc.Keys[name].X)
		}
		now := time.Unix(c.Now, 0)
		v, err := httpsig.Verify(c.Message.Build(), httpsig.VerifyOptions{Label: c.Label, Tag: c.Tag, Keys: keys,
			Now: func() time.Time { return now }, MaxAge: time.Duration(c.MaxAge) * time.Second, FieldTypes: doc.FieldTypes})
		got := "ok"
		var he *httpsig.Error
		if errors.As(err, &he) {
			got = he.Code
		} else if err != nil {
			got = err.Error()
		}
		if got != c.Expect {
			t.Errorf("%s: got %s (%v), want %s", c.Name, got, err, c.Expect)
		} else if err == nil && v.Label != c.Picked {
			t.Errorf("%s: verified %s, want %s", c.Name, v.Label, c.Picked)
		}
	}
}

type nonces map[string]bool

func (n nonces) Add(k string, _ time.Duration) bool {
	if n[k] {
		return false
	}
	n[k] = true
	return true
}

func TestReplay(t *testing.T) {
	doc := load(t)
	c := doc.Sign[2] // has a nonce
	priv := doc.Keys[c.Key].Private()
	m := c.Message.Build()
	m.Header.Set("Signature-Input", c.Headers["Signature-Input"])
	m.Header.Set("Signature", c.Headers["Signature"])
	o := httpsig.VerifyOptions{Keys: func(string) (ed25519.PublicKey, error) { return priv.Public().(ed25519.PublicKey), nil },
		Now: func() time.Time { return time.Unix(c.Params.Created+1, 0) }, Nonces: nonces{}, FieldTypes: doc.FieldTypes}
	if _, err := httpsig.Verify(m, o); err != nil {
		t.Fatal(err)
	}
	var he *httpsig.Error
	if _, err := httpsig.Verify(m, o); !errors.As(err, &he) || he.Code != "nonce_replayed" {
		t.Fatalf("replay: %v", err)
	}
}
