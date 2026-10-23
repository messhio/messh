package verify_test

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"messh.io/go/messh/verify"
)

type vcase struct {
	Name, Method, URL, Body, Expect string
	Headers                         map[string]string
	Now                             int64
	Keys                            verify.Directory `json:"-"`
	RawKeys                         json.RawMessage  `json:"directory_keys"`
}

func cases(t *testing.T) []vcase {
	b, err := os.ReadFile("../../../spec/vectors/web-bot-auth.json")
	if os.IsNotExist(err) {
		t.Skip("conformance vectors live in the messh monorepo (spec/vectors)")
	}
	if err != nil {
		t.Fatal(err)
	}
	var doc struct{ Verify []vcase }
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	for i := range doc.Verify {
		json.Unmarshal([]byte(`{"keys":`+string(doc.Verify[i].RawKeys)+`}`), &doc.Verify[i].Keys)
	}
	return doc.Verify
}

func request(c vcase) *http.Request {
	r := httptest.NewRequest(c.Method, c.URL, strings.NewReader(c.Body))
	for k, v := range c.Headers {
		r.Header.Set(k, v)
	}
	return r
}

func TestVerifyVectors(t *testing.T) {
	for _, c := range cases(t) {
		dir := c.Keys
		v, err := verify.New(verify.Trust("*"), verify.Registry("https://registry.example", ""),
			verify.StaticDirectory(&dir), verify.Clock(func() time.Time { return time.Unix(c.Now, 0) }))
		if err != nil {
			t.Fatal(err)
		}
		a, err := v.Verify(request(c))
		got := "ok"
		var ve *verify.Error
		if errors.As(err, &ve) {
			got = ve.Code
		} else if err != nil {
			got = err.Error()
		}
		if got != c.Expect {
			t.Errorf("%s: got %s, want %s (%v)", c.Name, got, c.Expect, err)
			continue
		}
		if got == "ok" {
			if a.Identity != "mukul" || a.KeyName != "sdk-test" {
				t.Errorf("%s: agent %+v", c.Name, a)
			}
			if _, err := v.Verify(request(c)); !errors.As(err, &ve) || ve.Code != "nonce_replayed" {
				t.Errorf("%s: replay not rejected: %v", c.Name, err)
			}
		}
	}
}

func TestTrustAndRegistry(t *testing.T) {
	c := cases(t)[0]
	dir := c.Keys
	clock := verify.Clock(func() time.Time { return time.Unix(c.Now, 0) })
	v, _ := verify.New(verify.Trust("alice"), verify.Registry("https://registry.example", ""), verify.StaticDirectory(&dir), clock)
	if _, err := v.Verify(request(c)); err == nil || err.(*verify.Error).Code != "untrusted" {
		t.Errorf("untrusted identity: %v", err)
	}
	v, _ = verify.New(verify.Trust("*"), verify.StaticDirectory(&dir), clock) // default registry messh.io only
	if _, err := v.Verify(request(c)); err == nil || err.(*verify.Error).Code != "untrusted" {
		t.Errorf("unknown registry: %v", err)
	}
	if _, err := verify.New(); err == nil {
		t.Error("New without Trust succeeded")
	}
}

func TestMiddleware(t *testing.T) {
	c := cases(t)[0]
	dir := c.Keys
	v, _ := verify.New(verify.Trust("mukul"), verify.Registry("https://registry.example", ""),
		verify.StaticDirectory(&dir), verify.Clock(func() time.Time { return time.Unix(c.Now, 0) }))
	h := v.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(verify.AgentFrom(r.Context()).Identity))
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, request(c))
	if rec.Code != 200 || rec.Body.String() != "mukul" {
		t.Errorf("signed: %d %s", rec.Code, rec.Body)
	}
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
	if rec.Code != 401 || rec.Header().Get("Accept-Signature") == "" {
		t.Errorf("unsigned: %d", rec.Code)
	}
}
