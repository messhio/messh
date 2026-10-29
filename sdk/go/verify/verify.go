// Package verify checks Web Bot Auth signatures on incoming requests and
// resolves signers through messh key directories, or through the key
// directories of other agents you trust.
//
//	v, err := verify.New(verify.Trust("mukul"))
//	http.ListenAndServe(":8080", v.Middleware(mux))
//	// in a handler: agent := verify.AgentFrom(r.Context())
package verify

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"messh.io/go/messh"
	"messh.io/go/messh/httpsig"
	"messh.io/go/messh/internal/sf"
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

func fromHTTPSig(err error) *Error {
	var he *httpsig.Error
	if errors.As(err, &he) {
		return &Error{Code: he.Code, Message: he.Message, Status: http.StatusUnauthorized}
	}
	var ve *Error
	if errors.As(err, &ve) {
		return ve
	}
	return fail(401, "bad_signature", "%v", err)
}

// Agent is a verified caller.
type Agent struct {
	Identity    string    // messh username, e.g. "mukul"; for other agents, their origin or jwk:<thumbprint>
	KeyName     string    // the key's name on messh, e.g. "laptop"
	KeyID       string    // RFC 7638 thumbprint
	Fingerprint string    // SHA256:… of the SSH key
	AgentURL    string    // Signature-Agent
	Created     time.Time // signature creation time

	External        bool // not a messh identity: an agent origin you trust, or inline keys
	SignedDirectory bool // the key's directory response carried a valid signature by that key
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

var defaultRequired = []string{"@method", "@authority", "@path", "signature-agent"}

// Verifier checks requests. Create it once and reuse it; it caches keys.
type Verifier struct {
	trust         []string
	registries    map[string]string // accepted Signature-Agent origin → fetch base URL
	maxSkew       time.Duration
	cacheTTL      time.Duration
	staleTTL      time.Duration
	maxBody       int64
	nonces        NonceStore
	http          *http.Client
	now           func() time.Time
	custom        func(ctx context.Context, agentURL, identity string) (*Directory, error)
	required      []string
	requireSigned bool
	scheme        string

	mu       sync.Mutex
	cache    map[string]cached
	seq      uint64
	fetching [fetchStripes]sync.Mutex
}

// cached is a key directory: dir is the last good answer (nil: no such
// identity), fetched at at (zero: none yet); failed is the last failed fetch;
// signed holds the key IDs the directory response signed.
type cached struct {
	dir    *Directory
	signed map[string]bool
	at     time.Time
	failed time.Time
	seq    uint64 // store order, for eviction
}

// Option configures a Verifier.
type Option func(*Verifier)

// Trust lists who may call: messh usernames ("mukul"), "*" for any messh
// identity, the origin of another Web Bot Auth agent ("https://agent.example",
// whose key directory is at <origin>/.well-known/http-message-signatures-directory),
// or jwk:<thumbprint> for a key sent inline in Signature-Agent. Required.
func Trust(patterns ...string) Option {
	return func(v *Verifier) {
		for _, p := range patterns {
			if strings.HasPrefix(p, "https://") || strings.HasPrefix(p, "http://") {
				p = strings.ToLower(strings.TrimRight(p, "/"))
			}
			v.trust = append(v.trust, p)
		}
	}
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

// RequireComponents replaces the components every signature must cover
// (default @method, @authority, @path, signature-agent), for agents that sign
// less. @target-uri counts for @authority, @path and @query, @request-target
// for @path and @query. Signature-Agent, a query, and a body (through
// content-digest) must be covered regardless.
func RequireComponents(names ...string) Option {
	return func(v *Verifier) { v.required = append([]string{}, names...) }
}

// RequireSignedDirectory ignores keys a fetched key directory doesn't sign
// (draft-meunier-http-message-signatures-directory §5). messh.io doesn't sign
// its directories yet, so this rejects messh identities for now.
func RequireSignedDirectory() Option { return func(v *Verifier) { v.requireSigned = true } }

// Scheme is the scheme clients used, when TLS ends at a proxy in front of
// the API (for @scheme and @target-uri). Default: from the request.
func Scheme(s string) Option { return func(v *Verifier) { v.scheme = s } }

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
// order: headers → coverage → digest → time → trust → key → signature →
// nonce; callers outside the trust list never cause a directory fetch.
func (v *Verifier) Verify(r *http.Request) (*Agent, error) {
	now := v.now()
	if r.Header.Get("Signature-Input") == "" || r.Header.Get("Signature") == "" {
		return nil, fail(401, "missing_signature", "send Signature, Signature-Input and Signature-Agent (Web Bot Auth)")
	}
	msg := httpsig.FromRequest(r, nil)
	if v.scheme != "" {
		msg.Scheme = v.scheme
	}
	sigs, err := httpsig.Signatures(msg)
	if err != nil {
		return nil, fromHTTPSig(err)
	}
	var sig *httpsig.Signature
	for _, s := range sigs {
		if s.Tag == wba.Tag {
			sig = s
			break
		}
	}
	if sig == nil {
		return nil, fail(401, "bad_signature", `no signature with tag="web-bot-auth"`)
	}
	if err := v.coverage(sig, r.URL.RawQuery != ""); err != nil {
		return nil, err
	}
	agentURL, err := agentOf(r.Header.Values("Signature-Agent"), sig)
	if err != nil {
		return nil, err
	}
	if sig.Alg != "" && sig.Alg != "ed25519" {
		return nil, fail(401, "bad_signature", "alg %q is not supported", sig.Alg)
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
	if sig.Covers("content-digest") {
		if err := httpsig.CheckDigest(strings.Join(r.Header.Values("Content-Digest"), ", "), body); err != nil {
			return nil, fromHTTPSig(err)
		}
	} else if len(body) > 0 {
		return nil, fail(401, "bad_signature", "a request body must be covered by content-digest")
	}
	msg.Body = body

	if sig.Created == 0 {
		return nil, fail(401, "bad_signature", "created is required")
	}
	ct := time.Unix(sig.Created, 0)
	if ct.After(now.Add(v.maxSkew)) || ct.Before(now.Add(-v.maxSkew)) {
		return nil, fail(401, "clock_skew", "created is %s from the server clock", now.Sub(ct).Round(time.Second))
	}
	if sig.Expires != 0 && (now.After(time.Unix(sig.Expires, 0)) || sig.Expires-sig.Created > wba.MaxLifetime) {
		return nil, fail(401, "clock_skew", "signature expired")
	}
	if sig.Nonce == "" {
		return nil, fail(401, "bad_signature", "nonce is required")
	}

	who, err := v.classify(agentURL, sig.KeyID)
	if err != nil {
		return nil, err
	}
	if !v.trusted(who) {
		return nil, fail(403, "untrusted", "%s is not in this API's trust list", who.identity)
	}
	var key *wba.JWK
	var signed bool
	keys := func(kid string) (ed25519.PublicKey, error) {
		k, pub, s, err := v.lookup(r.Context(), agentURL, who, kid)
		key, signed = k, s
		return pub, err
	}
	if _, err := httpsig.VerifySignature(msg, sig, httpsig.VerifyOptions{Keys: keys, Now: func() time.Time { return now },
		MaxSkew: v.maxSkew, MaxAge: v.maxSkew}); err != nil {
		return nil, fromHTTPSig(err)
	}
	if !v.nonces.Add(agentURL+" "+sig.Nonce, 2*v.maxSkew) {
		return nil, fail(401, "nonce_replayed", "this signature was already accepted once")
	}
	pub, _ := key.PublicKey()
	fp := key.Fingerprint
	if fp == "" {
		fp = wba.Fingerprint(pub)
	}
	return &Agent{Identity: who.identity, KeyName: key.Name, KeyID: sig.KeyID, Fingerprint: fp, AgentURL: agentURL,
		Created: ct, External: who.external, SignedDirectory: signed}, nil
}

// coverage checks the components the signature must cover.
func (v *Verifier) coverage(s *httpsig.Signature, hasQuery bool) error {
	covers := func(name string) bool {
		switch {
		case s.Covers(name):
			return true
		case name == "@authority":
			return s.Covers("@target-uri")
		case name == "@path" || name == "@query":
			return s.Covers("@target-uri") || s.Covers("@request-target")
		}
		return false
	}
	required := v.required
	if required == nil {
		required = defaultRequired
	}
	for _, c := range append(append([]string{}, required...), "signature-agent") {
		if !covers(c) {
			return fail(401, "bad_signature", "%s must be covered", c)
		}
	}
	if hasQuery && !covers("@query") {
		return fail(401, "bad_signature", "@query must be covered when the URL has a query")
	}
	return nil
}

// agentOf reads Signature-Agent: the dictionary member named by the covered
// component's key parameter, else a string, else the member named like the label.
func agentOf(values []string, s *httpsig.Signature) (string, error) {
	if len(values) == 0 {
		return "", fail(401, "bad_signature", "Signature-Agent header is missing")
	}
	header := strings.Join(values, ", ")
	for _, c := range s.Covered {
		if c.Name == "signature-agent" && c.Key != "" {
			d, _, err := sf.ParseDictionary(header)
			if err == nil {
				if m, ok := d.Get(c.Key); ok && !m.Inner && m.Bare.Kind == sf.String {
					return m.Bare.Str, nil
				}
			}
			return "", fail(401, "bad_signature", "Signature-Agent has no member %s", c.Key)
		}
	}
	if it, err := sf.ParseItem(header); err == nil && it.Bare.Kind == sf.String {
		return it.Bare.Str, nil
	}
	if d, _, err := sf.ParseDictionary(header); err == nil {
		if m, ok := d.Get(s.Label); ok && !m.Inner && m.Bare.Kind == sf.String {
			return m.Bare.Str, nil
		}
	}
	return "", fail(401, "bad_signature", "Signature-Agent has no value for %s", s.Label)
}

// signer is who a Signature-Agent names.
type signer struct {
	identity string
	external bool
	fetchURL string     // where its directory is
	inline   *Directory // keys sent in Signature-Agent itself
}

// classify maps Signature-Agent to a messh identity (<registry>/<user>), an
// agent origin, or inline keys, refusing anything else.
func (v *Verifier) classify(agentURL, keyID string) (signer, error) {
	if strings.HasPrefix(agentURL, "data:") {
		dir, err := parseDataURI(agentURL)
		if err != nil {
			return signer{}, fail(401, "bad_signature", "Signature-Agent: %v", err)
		}
		return signer{identity: "jwk:" + keyID, external: true, inline: dir}, nil
	}
	u, err := url.Parse(agentURL)
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return signer{}, fail(401, "bad_signature", "Signature-Agent is not a URL")
	}
	origin := u.Scheme + "://" + u.Host
	if base, ok := v.registries[origin]; ok {
		id := strings.Trim(u.Path, "/")
		if !identityRe.MatchString(id) {
			return signer{}, fail(401, "unknown_key", "Signature-Agent must be <registry>/<user>")
		}
		return signer{identity: id, fetchURL: base + "/" + id + wba.DirectoryPath}, nil
	}
	origin = strings.ToLower(origin)
	for _, t := range v.trust {
		if t != origin {
			continue
		}
		if (u.Path != "" && u.Path != "/") || u.RawQuery != "" {
			return signer{}, fail(403, "untrusted", "Signature-Agent %s: an agent outside messh is an origin, like %s", agentURL, origin)
		}
		return signer{identity: origin, external: true, fetchURL: origin + wba.DirectoryPath}, nil
	}
	return signer{}, fail(403, "untrusted", "Signature-Agent %s is not a messh registry or an agent this API trusts", agentURL)
}

func (v *Verifier) trusted(who signer) bool {
	for _, t := range v.trust {
		if t == who.identity || (t == "*" && !who.external) {
			return true
		}
	}
	return false
}

// parseDataURI reads an inline key directory:
// data:application/http-message-signatures-directory[+json][;base64],…
func parseDataURI(s string) (*Directory, error) {
	meta, data, ok := strings.Cut(strings.TrimPrefix(s, "data:"), ",")
	if !ok {
		return nil, errors.New("bad data URI")
	}
	isBase64 := strings.HasSuffix(meta, ";base64")
	mediaType, _, _ := strings.Cut(strings.TrimSuffix(meta, ";base64"), ";")
	switch strings.ToLower(strings.TrimSpace(mediaType)) {
	case "application/http-message-signatures-directory", "application/http-message-signatures-directory+json", "application/json":
	default:
		return nil, fmt.Errorf("data URI is %q, not a key directory", mediaType)
	}
	var raw []byte
	var err error
	if isBase64 {
		raw, err = base64.RawStdEncoding.DecodeString(strings.TrimRight(data, "="))
	} else {
		var u string
		u, err = url.PathUnescape(data)
		raw = []byte(u)
	}
	var dir Directory
	if err != nil || json.Unmarshal(raw, &dir) != nil || dir.Keys == nil {
		return nil, errors.New("data URI isn't a key directory")
	}
	return &dir, nil
}

// lookup finds the signer's key for kid. Directories are cached for
// CacheTTL; an unknown kid refetches at most every 30 s (so a key published a
// moment ago works), unknown identities are remembered the same way, one
// fetch per directory runs at a time, and while messh is unreachable cached
// keys keep working for StaleIfError.
func (v *Verifier) lookup(ctx context.Context, agentURL string, who signer, kid string) (*wba.JWK, ed25519.PublicKey, bool, error) {
	if who.inline != nil {
		k, pub, err := found(who.inline, agentURL, kid)
		return k, pub, false, err
	}
	if v.custom != nil {
		dir, err := v.custom(ctx, agentURL, who.identity)
		if err != nil {
			var ve *Error
			if errors.As(err, &ve) {
				return nil, nil, false, ve
			}
			return nil, nil, false, fail(401, "unknown_key", "key directory for %s: %v", agentURL, err)
		}
		k, pub, err := found(dir, agentURL, kid)
		return k, pub, false, err
	}
	now := v.now()
	e, ok := v.entry(agentURL)
	if ok && !e.at.IsZero() && now.Sub(e.at) < v.cacheTTL {
		if k, pub := find(e.dir, kid); k != nil {
			return k, pub, e.signed[kid], nil
		}
		if now.Sub(e.at) < minRefresh {
			k, pub, err := found(e.dir, agentURL, kid)
			return k, pub, false, err
		}
	}
	mu := &v.fetching[stripe(agentURL)]
	mu.Lock()
	defer mu.Unlock()
	e, ok = v.entry(agentURL)
	if ok && !e.at.IsZero() && now.Sub(e.at) < min(v.cacheTTL, minRefresh) {
		k, pub, err := found(e.dir, agentURL, kid) // fetched by another goroutine while this one waited
		return k, pub, k != nil && e.signed[kid], err
	}
	if !ok || e.failed.IsZero() || now.Sub(e.failed) >= retryAfter {
		// Shared by every waiting request, so one caller hanging up doesn't fail it.
		dir, signed, known := v.fetch(context.WithoutCancel(ctx), who.fetchURL)
		if known {
			v.store(agentURL, cached{dir: dir, signed: signed, at: now})
			k, pub, err := found(dir, agentURL, kid)
			return k, pub, k != nil && signed[kid], err
		}
		e.failed = now
		v.store(agentURL, e)
	}
	// The directory is unreachable: keep verifying with the cached one for a while.
	if !e.at.IsZero() && now.Sub(e.at) < v.staleTTL {
		k, pub, err := found(e.dir, agentURL, kid)
		return k, pub, k != nil && e.signed[kid], err
	}
	return nil, nil, false, fail(401, "unknown_key", "key directory for %s is unavailable", agentURL)
}

func find(dir *Directory, kid string) (*wba.JWK, ed25519.PublicKey) {
	if dir == nil {
		return nil, nil
	}
	for i := range dir.Keys {
		k := &dir.Keys[i]
		p, err := k.PublicKey()
		if err == nil && (k.Kid == kid || (k.Kid == "" && wba.Thumbprint(p) == kid)) {
			return k, p
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

// fetch gets a directory: (dir, signed, true); (nil, nil, true) for no such
// identity; (nil, nil, false) if it couldn't be fetched.
func (v *Verifier) fetch(ctx context.Context, fetchURL string) (*Directory, map[string]bool, bool) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fetchURL, nil)
	if err != nil {
		return nil, nil, false
	}
	req.Header.Set("Accept", "application/http-message-signatures-directory+json, application/json")
	req.Header.Set("User-Agent", "messh-go/"+messh.Version)
	resp, err := v.http.Do(req)
	if err != nil {
		return nil, nil, false
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, nil, true
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK || err != nil {
		return nil, nil, false
	}
	dir, signed, err := VerifyDirectory(fetchURL, resp.Header, body, v.now())
	if err != nil {
		return nil, nil, false
	}
	if v.requireSigned {
		var keep []wba.JWK
		for _, k := range dir.Keys {
			if signed[k.Kid] {
				keep = append(keep, k)
			}
		}
		dir.Keys = append([]wba.JWK{}, keep...)
	}
	return dir, signed, true
}

// VerifyDirectory reads a key directory response fetched from rawURL and
// returns its keys and the key IDs a valid directory signature covers: tag
// http-message-signatures-directory, signed by that key, binding the
// response to the authority it was fetched from
// (draft-meunier-http-message-signatures-directory §5).
func VerifyDirectory(rawURL string, header http.Header, body []byte, now time.Time) (*Directory, map[string]bool, error) {
	var dir Directory
	if err := json.Unmarshal(body, &dir); err != nil || dir.Keys == nil {
		return nil, nil, errors.New("verify: not a key directory")
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, nil, err
	}
	signed := map[string]bool{}
	req := &httpsig.Message{Method: http.MethodGet, Scheme: u.Scheme, Authority: u.Host, Path: u.EscapedPath(), Query: u.RawQuery, Header: http.Header{}}
	// The response carries the request's URL too, for directories signed over a plain "@authority".
	resp := &httpsig.Message{Status: http.StatusOK, Scheme: u.Scheme, Authority: u.Host, Path: u.EscapedPath(), Query: u.RawQuery,
		Header: header, Body: body, Request: req}
	sigs, err := httpsig.Signatures(resp)
	if err != nil {
		return &dir, signed, nil
	}
	for _, s := range sigs {
		if s.Tag != messh.DirectoryTag {
			continue
		}
		k, pub := find(&dir, s.KeyID)
		if k == nil {
			continue
		}
		o := httpsig.VerifyOptions{Keys: func(string) (ed25519.PublicKey, error) { return pub, nil }, Now: func() time.Time { return now }}
		if _, err := httpsig.VerifySignature(resp, s, o); err == nil {
			signed[s.KeyID] = true
		}
	}
	return &dir, signed, nil
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
