// Package verify checks Web Bot Auth signatures on incoming requests and
// resolves signers through messh key directories.
//
//	v, err := verify.New(verify.Trust("mukul"))
//	http.ListenAndServe(":8080", v.Middleware(mux))
//	// in a handler: agent := verify.AgentFrom(r.Context())
package verify

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"messh.io/go/messh"
	"messh.io/go/messh/internal/wba"
)

// Error is a verification failure. Code and Status follow the messh spec:
// missing_signature, bad_signature, digest_mismatch, clock_skew,
// nonce_replayed, unknown_key (401); untrusted (403); body_too_large (413).
type Error struct {
	Code    string `json:"error"`
	Message string `json:"message"`
	Status  int    `json:"-"`
}

func (e *Error) Error() string { return e.Code + ": " + e.Message }

func fail(status int, code, format string, a ...any) *Error {
	return &Error{Code: code, Message: fmt.Sprintf(format, a...), Status: status}
}

// Agent is a verified caller.
type Agent struct {
	Identity    string    // messh username, e.g. "mukul"
	KeyName     string    // the key's name on messh, e.g. "laptop"
	KeyID       string    // RFC 7638 thumbprint
	Fingerprint string    // SHA256:… of the SSH key
	AgentURL    string    // Signature-Agent
	Created     time.Time // signature creation time
}

// Directory is a key directory (JWKS of Ed25519 keys).
type Directory = wba.Directory

// NonceStore remembers nonces for replay protection. Add returns false if
// key was already seen within ttl. Use a shared store (Redis) when you run
// more than one instance.
type NonceStore interface {
	Add(key string, ttl time.Duration) bool
}

// Directory cache policy, the same in every messh SDK.
const (
	minRefresh   = 30 * time.Second // an unknown keyid refetches its signer's directory at most this often
	retryAfter   = 5 * time.Second  // while messh is unreachable, retry a directory at most this often
	maxEntries   = 10000            // directories kept at most
	fetchStripes = 64               // fetch locks: one fetch per directory at a time
)

// DefaultMaxBodyBytes is the default limit on request bodies Verify reads.
const DefaultMaxBodyBytes = 1 << 20

// Verifier checks requests. Create it once and reuse it; it caches keys.
type Verifier struct {
	trust      []string
	registries map[string]string // accepted Signature-Agent origin → fetch base URL
	maxSkew    time.Duration
	cacheTTL   time.Duration
	staleTTL   time.Duration
	maxBody    int64
	nonces     NonceStore
	http       *http.Client
	now        func() time.Time
	custom     func(ctx context.Context, agentURL, identity string) (*Directory, error)

	mu       sync.Mutex
	cache    map[string]cached
	seq      uint64
	fetching [fetchStripes]sync.Mutex
}

// cached is a key directory: dir is the last good answer (nil: no such
// identity), fetched at at (zero: none yet); failed is the last failed fetch.
type cached struct {
	dir    *Directory
	at     time.Time
	failed time.Time
	seq    uint64 // store order, for eviction
}

// Option configures a Verifier.
type Option func(*Verifier)

// Trust lists who may call: messh usernames ("mukul") or "*" for anyone
// with a valid messh signature. Required.
func Trust(patterns ...string) Option {
	return func(v *Verifier) { v.trust = append(v.trust, patterns...) }
}

// Registry accepts Signature-Agent URLs under origin (default
// https://messh.io). fetchBase, if non-empty, is where directories are
// actually fetched from (e.g. an internal hostname).
func Registry(origin, fetchBase string) Option {
	return func(v *Verifier) {
		origin = strings.TrimRight(origin, "/")
		if fetchBase == "" {
			fetchBase = origin
		}
		v.registries[origin] = strings.TrimRight(fetchBase, "/")
	}
}

// MaxSkew bounds |now − created|. Default 60s.
func MaxSkew(d time.Duration) Option { return func(v *Verifier) { v.maxSkew = d } }

// CacheTTL is how long a key directory is reused. Default 5 min.
func CacheTTL(d time.Duration) Option { return func(v *Verifier) { v.cacheTTL = d } }

// StaleIfError keeps using a cached directory this long when messh is
// unreachable. Default 1 h.
func StaleIfError(d time.Duration) Option { return func(v *Verifier) { v.staleTTL = d } }

// Nonces sets the replay store. Default: in memory.
func Nonces(s NonceStore) Option { return func(v *Verifier) { v.nonces = s } }

// HTTPClient sets the client used to fetch directories. Default timeout 5s.
func HTTPClient(h *http.Client) Option { return func(v *Verifier) { v.http = h } }

// Clock overrides time (tests).
func Clock(now func() time.Time) Option { return func(v *Verifier) { v.now = now } }

// MaxBodyBytes limits the request bodies Verify reads; bigger ones get 413
// body_too_large. Default 1 MiB.
func MaxBodyBytes(n int64) Option { return func(v *Verifier) { v.maxBody = n } }

// StaticDirectory resolves every agent to fixed keys (tests, air-gapped setups).
func StaticDirectory(dir *Directory) Option {
	return DirectoryFunc(func(context.Context, string, string) (*Directory, error) { return dir, nil })
}

// DirectoryFunc resolves directories yourself (tests, air-gapped setups),
// bypassing fetches and the cache. A nil directory means no such identity.
func DirectoryFunc(f func(ctx context.Context, agentURL, identity string) (*Directory, error)) Option {
	return func(v *Verifier) { v.custom = f }
}

// New creates a Verifier. Trust is required.
func New(opts ...Option) (*Verifier, error) {
	v := &Verifier{
		registries: map[string]string{}, maxSkew: 60 * time.Second, cacheTTL: 5 * time.Minute,
		staleTTL: time.Hour, maxBody: DefaultMaxBodyBytes, nonces: NewMemoryNonces(),
		http: &http.Client{Timeout: 5 * time.Second}, now: time.Now, cache: map[string]cached{},
	}
	for _, o := range opts {
		o(v)
	}
	if len(v.trust) == 0 {
		return nil, errors.New("verify: Trust(...) is required")
	}
	if len(v.registries) == 0 {
		v.registries["https://messh.io"] = "https://messh.io"
	}
	return v, nil
}

var identityRe = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{1,28}[a-z0-9])$`)

// Verify checks r. On success the body is still readable. Checks run in
// order: headers → digest → time → trust → key → signature → nonce; callers
// outside the trust list never cause a directory fetch.
func (v *Verifier) Verify(r *http.Request) (*Agent, error) {
	now := v.now()
	input, sigHeader, agentHeader := r.Header.Get("Signature-Input"), r.Header.Get("Signature"), r.Header.Get("Signature-Agent")
	if input == "" || sigHeader == "" {
		return nil, fail(401, "missing_signature", "send Signature, Signature-Input and Signature-Agent (Web Bot Auth)")
	}
	sp, err := wba.PickWebBotAuth(input)
	if err != nil {
		return nil, fail(401, "bad_signature", "%v", err)
	}
	sig, err := wba.SignatureBytes(sigHeader, sp.Label)
	if err != nil {
		return nil, fail(401, "bad_signature", "%v", err)
	}
	for _, c := range []string{"@method", "@authority", "@path", "signature-agent"} {
		if !sp.Covers(c) {
			return nil, fail(401, "bad_signature", "%s must be covered", c)
		}
	}
	if r.URL.RawQuery != "" && !sp.Covers("@query") {
		return nil, fail(401, "bad_signature", "@query must be covered when the URL has a query")
	}
	if agentHeader == "" {
		return nil, fail(401, "bad_signature", "Signature-Agent header is missing")
	}
	agentURL, err := wba.ParseAgent(agentHeader, sp.Label)
	if err != nil {
		return nil, fail(401, "bad_signature", "%v", err)
	}
	if alg, ok := sp.Params["alg"]; ok && alg != "ed25519" {
		return nil, fail(401, "bad_signature", "alg %q is not supported", alg)
	}

	var body []byte
	if r.Body != nil {
		body, err = io.ReadAll(io.LimitReader(r.Body, v.maxBody+1))
		if err != nil {
			return nil, fail(400, "bad_request", "unreadable body")
		}
		if int64(len(body)) > v.maxBody {
			return nil, fail(413, "body_too_large", "the request body is over this API's limit of %d bytes", v.maxBody)
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
	}
	if sp.Covers("content-digest") {
		if r.Header.Get("Content-Digest") != wba.ContentDigest(body) {
			return nil, fail(401, "digest_mismatch", "the body doesn't match Content-Digest")
		}
	} else if len(body) > 0 {
		return nil, fail(401, "bad_signature", "a request body must be covered by content-digest")
	}

	created, err := strconv.ParseInt(sp.Params["created"], 10, 64)
	if err != nil {
		return nil, fail(401, "bad_signature", "created is required")
	}
	ct := time.Unix(created, 0)
	if ct.After(now.Add(v.maxSkew)) || ct.Before(now.Add(-v.maxSkew)) {
		return nil, fail(401, "clock_skew", "created is %s from the server clock", now.Sub(ct).Round(time.Second))
	}
	if e, ok := sp.Params["expires"]; ok {
		exp, err := strconv.ParseInt(e, 10, 64)
		if err != nil || now.After(time.Unix(exp, 0)) || exp-created > wba.MaxLifetime {
			return nil, fail(401, "clock_skew", "signature expired")
		}
	}
	nonce := sp.Params["nonce"]
	if nonce == "" {
		return nil, fail(401, "bad_signature", "nonce is required")
	}

	identity, err := v.identity(agentURL)
	if err != nil {
		return nil, err
	}
	if !v.trusted(identity) {
		return nil, fail(403, "untrusted", "%s is not in this API's trust list", identity)
	}
	kid := sp.Params["keyid"]
	key, pub, err := v.lookup(r.Context(), agentURL, identity, kid)
	if err != nil {
		return nil, err
	}

	host := r.Host
	if host == "" {
		host = r.URL.Host
	}
	path := r.URL.EscapedPath()
	if path == "" {
		path = "/"
	}
	values := map[string]string{"@method": strings.ToUpper(r.Method), "@authority": strings.ToLower(host), "@path": path, "@query": "?" + r.URL.RawQuery}
	comps := make([]wba.Component, 0, len(sp.Components))
	for _, c := range sp.Components {
		val, ok := values[c]
		if !ok {
			if strings.HasPrefix(c, "@") {
				return nil, fail(401, "bad_signature", "unsupported component %s", c)
			}
			hv := r.Header.Values(c)
			if len(hv) == 0 {
				return nil, fail(401, "bad_signature", "covered header %s is missing", c)
			}
			for i := range hv {
				hv[i] = strings.TrimSpace(hv[i])
			}
			val = strings.Join(hv, ", ")
		}
		comps = append(comps, wba.Component{Name: c, Value: val})
	}
	if !ed25519.Verify(pub, wba.Base(comps, sp.Raw), sig) {
		return nil, fail(401, "bad_signature", "the signature doesn't match the request")
	}
	if !v.nonces.Add(agentURL+" "+nonce, 2*v.maxSkew) {
		return nil, fail(401, "nonce_replayed", "this signature was already accepted once")
	}
	return &Agent{Identity: identity, KeyName: key.Name, KeyID: kid, Fingerprint: key.Fingerprint, AgentURL: agentURL, Created: ct}, nil
}

func (v *Verifier) trusted(identity string) bool {
	for _, t := range v.trust {
		if t == "*" || t == identity {
			return true
		}
	}
	return false
}

// identity maps <registry>/<user> to user, refusing registries not configured.
func (v *Verifier) identity(agentURL string) (string, error) {
	u, err := url.Parse(agentURL)
	if err != nil || u.Host == "" {
		return "", fail(401, "bad_signature", "Signature-Agent is not a URL")
	}
	if _, ok := v.registries[u.Scheme+"://"+u.Host]; !ok {
		return "", fail(403, "untrusted", "Signature-Agent %s is not a messh registry this API accepts", agentURL)
	}
	id := strings.Trim(u.Path, "/")
	if !identityRe.MatchString(id) {
		return "", fail(401, "unknown_key", "Signature-Agent must be <registry>/<user>")
	}
	return id, nil
}

// lookup finds the signer's key for kid. Directories are cached for
// CacheTTL; an unknown kid refetches at most every 30 s (so a key published a
// moment ago works), unknown identities are remembered the same way, one
// fetch per directory runs at a time, and while messh is unreachable cached
// keys keep working for StaleIfError.
func (v *Verifier) lookup(ctx context.Context, agentURL, identity, kid string) (*wba.JWK, ed25519.PublicKey, error) {
	if v.custom != nil {
		dir, err := v.custom(ctx, agentURL, identity)
		if err != nil {
			var ve *Error
			if errors.As(err, &ve) {
				return nil, nil, ve
			}
			return nil, nil, fail(401, "unknown_key", "key directory for %s: %v", agentURL, err)
		}
		return found(dir, agentURL, kid)
	}
	now := v.now()
	e, ok := v.entry(agentURL)
	if ok && !e.at.IsZero() && now.Sub(e.at) < v.cacheTTL {
		if k, pub := find(e.dir, kid); k != nil {
			return k, pub, nil
		}
		if now.Sub(e.at) < minRefresh {
			return found(e.dir, agentURL, kid)
		}
	}
	mu := &v.fetching[stripe(agentURL)]
	mu.Lock()
	defer mu.Unlock()
	e, ok = v.entry(agentURL)
	if ok && !e.at.IsZero() && now.Sub(e.at) < min(v.cacheTTL, minRefresh) {
		return found(e.dir, agentURL, kid) // fetched by another goroutine while this one waited
	}
	if !ok || e.failed.IsZero() || now.Sub(e.failed) >= retryAfter {
		// Shared by every waiting request, so one caller hanging up doesn't fail it.
		dir, known := v.fetch(context.WithoutCancel(ctx), agentURL, identity)
		if known {
			v.store(agentURL, cached{dir: dir, at: now})
			return found(dir, agentURL, kid)
		}
		e.failed = now
		v.store(agentURL, e)
	}
	// messh is unreachable: keep verifying with the cached directory for a while.
	if !e.at.IsZero() && now.Sub(e.at) < v.staleTTL {
		return found(e.dir, agentURL, kid)
	}
	return nil, nil, fail(401, "unknown_key", "key directory for %s is unavailable", agentURL)
}

func find(dir *Directory, kid string) (*wba.JWK, ed25519.PublicKey) {
	if dir == nil {
		return nil, nil
	}
	for i := range dir.Keys {
		if dir.Keys[i].Kid == kid {
			if p, err := dir.Keys[i].PublicKey(); err == nil {
				return &dir.Keys[i], p
			}
		}
	}
	return nil, nil
}

func found(dir *Directory, agentURL, kid string) (*wba.JWK, ed25519.PublicKey, error) {
	if k, pub := find(dir, kid); k != nil {
		return k, pub, nil
	}
	if dir == nil {
		return nil, nil, fail(401, "unknown_key", "there's no messh identity at %s", agentURL)
	}
	return nil, nil, fail(401, "unknown_key", "keyid %s is not an active key of %s; publish it with messh publish", kid, agentURL)
}

func stripe(key string) int {
	h := fnv.New32a()
	h.Write([]byte(key))
	return int(h.Sum32() % fetchStripes)
}

func (v *Verifier) entry(agentURL string) (cached, bool) {
	v.mu.Lock()
	defer v.mu.Unlock()
	e, ok := v.cache[agentURL]
	return e, ok
}

func (v *Verifier) store(agentURL string, e cached) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.seq++
	e.seq = v.seq
	v.cache[agentURL] = e
	if len(v.cache) > maxEntries {
		oldest, seq := "", e.seq
		for k, c := range v.cache {
			if c.seq < seq {
				oldest, seq = k, c.seq
			}
		}
		delete(v.cache, oldest)
	}
}

// fetch gets a directory: (dir, true); (nil, true) for no such identity;
// (nil, false) if messh couldn't answer.
func (v *Verifier) fetch(ctx context.Context, agentURL, identity string) (*Directory, bool) {
	u, _ := url.Parse(agentURL)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, v.registries[u.Scheme+"://"+u.Host]+"/"+identity+wba.DirectoryPath, nil)
	if err != nil {
		return nil, false
	}
	req.Header.Set("Accept", "application/http-message-signatures-directory+json, application/json")
	req.Header.Set("User-Agent", "messh-go/"+messh.Version)
	resp, err := v.http.Do(req)
	if err != nil {
		return nil, false
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, true
	}
	var d Directory
	if resp.StatusCode != http.StatusOK || json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&d) != nil || d.Keys == nil {
		return nil, false
	}
	return &d, true
}

// AcceptSignature is the RFC 9421 §5.1 hint sent with 401 responses.
const AcceptSignature = `sig1=("@method" "@authority" "@path" "signature-agent");keyid;created;expires;nonce;alg="ed25519";tag="web-bot-auth"`

type ctxKey struct{}

// Middleware verifies every request before next runs. Failures get a JSON
// error ({"error": code, "message": …}) and, for 401, Accept-Signature.
func (v *Verifier) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a, err := v.Verify(r)
		if err != nil {
			var ve *Error
			if !errors.As(err, &ve) {
				ve = fail(401, "bad_signature", "%v", err)
			}
			if ve.Status == 401 {
				w.Header().Set("Accept-Signature", AcceptSignature)
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(ve.Status)
			json.NewEncoder(w).Encode(ve)
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, a)))
	})
}

// AgentFrom returns the verified caller stored by Middleware, or nil.
func AgentFrom(ctx context.Context) *Agent {
	a, _ := ctx.Value(ctxKey{}).(*Agent)
	return a
}

// MemoryNonces is an in-process NonceStore.
type MemoryNonces struct {
	mu   sync.Mutex
	seen map[string]time.Time
}

func NewMemoryNonces() *MemoryNonces { return &MemoryNonces{seen: map[string]time.Time{}} }

func (m *MemoryNonces) Add(key string, ttl time.Duration) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	for k, exp := range m.seen {
		if now.After(exp) {
			delete(m.seen, k)
		}
	}
	if _, dup := m.seen[key]; dup {
		return false
	}
	m.seen[key] = now.Add(ttl)
	return true
}
