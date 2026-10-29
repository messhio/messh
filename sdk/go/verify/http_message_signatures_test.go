package verify_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"
	"time"

	"messh.io/go/messh/internal/vectors"
	"messh.io/go/messh/internal/wba"
	"messh.io/go/messh/verify"
)

func load(t *testing.T) *vectors.Doc {
	doc, ok := vectors.Load()
	if !ok {
		t.Skip("vectors live in the messh repo (spec/vectors)")
	}
	return doc
}

func TestWebBotAuthVectors(t *testing.T) {
	doc := load(t)
	for _, c := range doc.WebBotAuth.Cases {
		dirs := func(_ context.Context, agentURL, _ string) (*verify.Directory, error) {
			names, ok := c.Directories[agentURL]
			if !ok {
				return nil, nil
			}
			d := &verify.Directory{Keys: nil}
			for _, n := range names {
				k := doc.Keys[n]
				d.Keys = append(d.Keys, wba.JWK{Kty: "OKP", Crv: "Ed25519", X: k.X, Kid: k.Thumbprint})
			}
			return d, nil
		}
		now := time.Unix(c.Now, 0)
		opts := []verify.Option{verify.Trust(c.Trust...), verify.Registry(doc.WebBotAuth.Registry, ""),
			verify.Clock(func() time.Time { return now }), verify.DirectoryFunc(dirs)}
		if c.Require != nil {
			opts = append(opts, verify.RequireComponents(c.Require...))
		}
		v, err := verify.New(opts...)
		if err != nil {
			t.Fatal(err)
		}
		body := ""
		if c.Message.Body != nil {
			body = *c.Message.Body
		}
		r := httptest.NewRequest(c.Message.Method, c.Message.URL, strings.NewReader(body))
		for _, h := range c.Message.Headers {
			r.Header.Add(h[0], h[1])
		}
		a, err := v.Verify(r)
		got := "ok"
		var ve *verify.Error
		if errors.As(err, &ve) {
			got = ve.Code
		} else if err != nil {
			got = err.Error()
		}
		switch {
		case got != c.Expect:
			t.Errorf("%s: got %s (%v), want %s", c.Name, got, err, c.Expect)
		case err == nil && (a.Identity != c.Identity || a.External != c.External):
			t.Errorf("%s: got %s external=%v, want %s external=%v", c.Name, a.Identity, a.External, c.Identity, c.External)
		}
	}
}

func TestDirectorySignatureVectors(t *testing.T) {
	doc := load(t)
	for _, c := range doc.Directory.Verify {
		h := http.Header{}
		for k, v := range c.Headers {
			h.Set(k, v)
		}
		_, signed, err := verify.VerifyDirectory(c.URL, h, []byte(c.Body), time.Unix(c.Now, 0))
		if err != nil {
			t.Errorf("%s: %v", c.Name, err)
			continue
		}
		var got []string
		for k := range signed {
			got = append(got, k)
		}
		sort.Strings(got)
		want := append([]string{}, c.Signed...)
		sort.Strings(want)
		if strings.Join(got, ",") != strings.Join(want, ",") {
			t.Errorf("%s: signed %v, want %v", c.Name, got, want)
		}
	}
}
