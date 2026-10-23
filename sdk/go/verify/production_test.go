package verify_test

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"messh.io/go/messh"
	"messh.io/go/messh/verify"
)

// registry is a fake messh: dirs[identity] is a directory, "" for 404, "error" for 500.
type registry struct {
	*httptest.Server
	mu   sync.Mutex
	dirs map[string]string
	hits int
}

func newRegistry(dirs map[string]string) *registry {
	r := &registry{dirs: dirs}
	r.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		r.mu.Lock()
		r.hits++
		d := r.dirs[strings.Split(req.URL.Path, "/")[1]]
		r.mu.Unlock()
		time.Sleep(50 * time.Millisecond) // long enough for concurrent misses to overlap
		switch d {
		case "":
			http.NotFound(w, req)
		case "error":
			w.WriteHeader(500)
		default:
			w.Write([]byte(d))
		}
	}))
	return r
}

func (r *registry) set(id, d string) { r.mu.Lock(); r.dirs[id] = d; r.mu.Unlock() }
func (r *registry) count() int       { r.mu.Lock(); defer r.mu.Unlock(); return r.hits }

type setup struct {
	reg  *registry
	t    time.Time
	mu   sync.Mutex
	v    *verify.Verifier
	key  string
	jwks string
}

func newSetup(t *testing.T, dirs map[string]string, opts ...verify.Option) *setup {
	b, err := os.ReadFile("../../../spec/vectors/web-bot-auth.json")
	if os.IsNotExist(err) {
		t.Skip("conformance vectors live in the messh monorepo (spec/vectors)")
	}
	var doc struct {
		Key struct {
			Files struct{ Openssh string }
			JWK   json.RawMessage `json:"jwk"`
		}
	}
	json.Unmarshal(b, &doc)
	s := &setup{t: time.Unix(1_800_000_000, 0), key: filepath.Join("../../../spec/vectors", doc.Key.Files.Openssh), jwks: `{"keys":[` + string(doc.Key.JWK) + `]}`}
	for id, d := range dirs {
		if d == "KEY" {
			dirs[id] = s.jwks
		}
	}
	s.reg = newRegistry(dirs)
	t.Cleanup(s.reg.Close)
	s.v, err = verify.New(append([]verify.Option{verify.Trust("*"), verify.Registry(s.reg.URL, ""), verify.Clock(s.now)}, opts...)...)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func (s *setup) now() time.Time          { s.mu.Lock(); defer s.mu.Unlock(); return s.t }
func (s *setup) advance(d time.Duration) { s.mu.Lock(); s.t = s.t.Add(d); s.mu.Unlock() }
func (s *setup) send(t *testing.T, id string) string {
	c, err := messh.NewClient(id, messh.WithKey(messh.KeyFile(s.key)), messh.WithRegistry(s.reg.URL), messh.WithClock(s.now))
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("GET", "https://api.example/hello", nil)
	if err := c.Sign(req); err != nil {
		t.Fatal(err)
	}
	_, err = s.v.Verify(req)
	var ve *verify.Error
	if errors.As(err, &ve) {
		return ve.Code
	}
	if err != nil {
		return err.Error()
	}
	return "ok"
}

func TestUntrustedCallersNeverTriggerAFetch(t *testing.T) {
	s := newSetup(t, map[string]string{"mukul": "KEY"})
	s.v, _ = verify.New(verify.Trust("alice"), verify.Registry(s.reg.URL, ""), verify.Clock(s.now))
	if got := s.send(t, "mukul"); got != "untrusted" || s.reg.count() != 0 {
		t.Fatalf("got %s after %d fetches", got, s.reg.count())
	}
}

func TestUnknownIdentitiesAreRemembered(t *testing.T) {
	s := newSetup(t, map[string]string{})
	if got := s.send(t, "ghost"); got != "unknown_key" {
		t.Fatal(got)
	}
	s.advance(10 * time.Second)
	if got := s.send(t, "ghost"); got != "unknown_key" || s.reg.count() != 1 {
		t.Fatalf("%s after %d fetches", got, s.reg.count())
	}
	s.advance(21 * time.Second)
	s.send(t, "ghost")
	if s.reg.count() != 2 {
		t.Fatalf("refetch after 30 s: %d fetches", s.reg.count())
	}
}

func TestNewKeysWorkWithin30s(t *testing.T) {
	s := newSetup(t, map[string]string{"mukul": `{"keys":[]}`})
	if got := s.send(t, "mukul"); got != "unknown_key" {
		t.Fatal(got)
	}
	s.reg.set("mukul", s.jwks)
	s.advance(10 * time.Second)
	if got := s.send(t, "mukul"); got != "unknown_key" {
		t.Fatalf("refetched within 30 s: %s", got)
	}
	s.advance(21 * time.Second)
	if got := s.send(t, "mukul"); got != "ok" {
		t.Fatal(got)
	}
	s.advance(60 * time.Second)
	if got := s.send(t, "mukul"); got != "ok" || s.reg.count() != 2 {
		t.Fatalf("%s after %d fetches", got, s.reg.count())
	}
}

func TestNotFoundIsNeverStaleButAnOutageIs(t *testing.T) {
	s := newSetup(t, map[string]string{"mukul": "KEY"})
	if got := s.send(t, "mukul"); got != "ok" {
		t.Fatal(got)
	}
	s.reg.set("mukul", "error")
	s.advance(301 * time.Second)
	if got := s.send(t, "mukul"); got != "ok" {
		t.Fatalf("outage: %s", got)
	}
	s.advance(2 * time.Second)
	if got := s.send(t, "mukul"); got != "ok" || s.reg.count() != 2 {
		t.Fatalf("back-off: %s after %d fetches", got, s.reg.count())
	}
	s.reg.set("mukul", "")
	s.advance(5 * time.Second)
	if got := s.send(t, "mukul"); got != "unknown_key" {
		t.Fatalf("deleted identity served stale: %s", got)
	}
}

func TestConcurrentMissesShareOneFetch(t *testing.T) {
	s := newSetup(t, map[string]string{"mukul": "KEY"})
	var wg sync.WaitGroup
	got := make([]string, 4)
	for i := range got {
		wg.Add(1)
		go func(i int) { defer wg.Done(); got[i] = s.send(t, "mukul") }(i)
	}
	wg.Wait()
	if strings.Join(got, ",") != "ok,ok,ok,ok" || s.reg.count() != 1 {
		t.Fatalf("%v after %d fetches", got, s.reg.count())
	}
}

func TestBodiesOverTheLimitGet413(t *testing.T) {
	s := newSetup(t, map[string]string{"mukul": "KEY"}, verify.MaxBodyBytes(8))
	c, _ := messh.NewClient("mukul", messh.WithKey(messh.KeyFile(s.key)), messh.WithRegistry(s.reg.URL), messh.WithClock(s.now))
	req := httptest.NewRequest("POST", "https://api.example/x", strings.NewReader("0123456789"))
	if err := c.Sign(req); err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	s.v.Middleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("handler ran") })).ServeHTTP(rec, req)
	if rec.Code != 413 || !strings.Contains(rec.Body.String(), "body_too_large") {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
}
