// Package webbotauth signs and verifies HTTP requests with Web Bot Auth:
// RFC 9421 message signatures, Ed25519, tag="web-bot-auth", a
// Signature-Agent header naming who signed, and keys published as a JWKS at
// <agent>/.well-known/http-message-signatures-directory.
//
// messh is the key directory: the agent for user mukul is <registry>/mukul,
// and its directory lists mukul's published ssh-ed25519 keys.
package webbotauth

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	Tag                = "web-bot-auth"
	DirectoryPath      = "/.well-known/http-message-signatures-directory"
	DirectoryMediaType = "application/http-message-signatures-directory+json"
	Label              = "sig1"
	Lifetime           = 60 * time.Second
)

// JWK is an Ed25519 public key (RFC 8037). Kid is its RFC 7638 thumbprint,
// which is also the keyid in Signature-Input. The messh_* members are extras.
type JWK struct {
	Kty         string `json:"kty"`
	Crv         string `json:"crv"`
	X           string `json:"x"`
	Kid         string `json:"kid"`
	Name        string `json:"messh_name,omitempty"`
	Fingerprint string `json:"messh_fingerprint,omitempty"`
}

type Directory struct {
	Keys []JWK `json:"keys"`
}

var b64url = base64.RawURLEncoding

// Thumbprint is the RFC 7638 JWK thumbprint of an Ed25519 key.
func Thumbprint(pub ed25519.PublicKey) string {
	h := sha256.Sum256([]byte(`{"crv":"Ed25519","kty":"OKP","x":"` + b64url.EncodeToString(pub) + `"}`))
	return b64url.EncodeToString(h[:])
}

func NewJWK(pub ed25519.PublicKey, name, fingerprint string) JWK {
	return JWK{Kty: "OKP", Crv: "Ed25519", X: b64url.EncodeToString(pub), Kid: Thumbprint(pub), Name: name, Fingerprint: fingerprint}
}

func (k JWK) PublicKey() (ed25519.PublicKey, error) {
	b, err := b64url.DecodeString(k.X)
	if err != nil || k.Kty != "OKP" || k.Crv != "Ed25519" || len(b) != ed25519.PublicKeySize {
		return nil, errors.New("not an Ed25519 JWK")
	}
	return b, nil
}

// Signer signs raw bytes with Ed25519 (a key file or ssh-agent).
type Signer interface {
	Public() ed25519.PublicKey
	Sign(data []byte) ([]byte, error)
}

// Sign adds Signature-Agent, Signature-Input and Signature to req. A body,
// if present, is covered through Content-Digest (RFC 9530).
func Sign(req *http.Request, s Signer, agent string, now time.Time, nonce string) error {
	req.Header.Set("Signature-Agent", strconv.Quote(agent))
	components := []string{"@method", "@authority", "@path"}
	if req.URL.RawQuery != "" {
		components = append(components, "@query")
	}
	if req.Body != nil && req.Body != http.NoBody {
		body, err := io.ReadAll(req.Body)
		if err != nil {
			return err
		}
		req.Body = io.NopCloser(bytes.NewReader(body))
		req.Header.Set("Content-Digest", contentDigest(body))
		components = append(components, "content-digest")
	}
	components = append(components, "signature-agent")

	quoted := make([]string, len(components))
	for i, c := range components {
		quoted[i] = strconv.Quote(c)
	}
	params := fmt.Sprintf(`(%s);created=%d;expires=%d;keyid=%q;alg="ed25519";nonce=%q;tag=%q`,
		strings.Join(quoted, " "), now.Unix(), now.Add(Lifetime).Unix(), Thumbprint(s.Public()), nonce, Tag)
	base, err := signatureBase(req, components, params)
	if err != nil {
		return err
	}
	sig, err := s.Sign(base)
	if err != nil {
		return err
	}
	req.Header.Set("Signature-Input", Label+"="+params)
	req.Header.Set("Signature", Label+"=:"+base64.StdEncoding.EncodeToString(sig)+":")
	return nil
}

func contentDigest(body []byte) string {
	h := sha256.Sum256(body)
	return "sha-256=:" + base64.StdEncoding.EncodeToString(h[:]) + ":"
}

func authority(req *http.Request) string {
	h := req.Host
	if h == "" {
		h = req.URL.Host
	}
	return strings.ToLower(h)
}

func componentValue(req *http.Request, name string) (string, error) {
	switch name {
	case "@method":
		return strings.ToUpper(req.Method), nil
	case "@authority":
		return authority(req), nil
	case "@path":
		if p := req.URL.EscapedPath(); p != "" {
			return p, nil
		}
		return "/", nil
	case "@query":
		return "?" + req.URL.RawQuery, nil
	}
	if strings.HasPrefix(name, "@") {
		return "", fmt.Errorf("unsupported component %s", name)
	}
	vals := req.Header.Values(name)
	if len(vals) == 0 {
		return "", fmt.Errorf("covered header %s is missing", name)
	}
	for i := range vals {
		vals[i] = strings.TrimSpace(vals[i])
	}
	return strings.Join(vals, ", "), nil
}

// signatureBase builds the RFC 9421 §2.5 signature base.
func signatureBase(req *http.Request, components []string, params string) ([]byte, error) {
	var b strings.Builder
	for _, c := range components {
		v, err := componentValue(req, c)
		if err != nil {
			return nil, err
		}
		fmt.Fprintf(&b, "%q: %s\n", c, v)
	}
	fmt.Fprintf(&b, "\"@signature-params\": %s", params)
	return []byte(b.String()), nil
}

// --- verification ---

// Error carries a messh error code (06-signed-requests-spec.md) and HTTP status.
type Error struct {
	Code    string `json:"error"`
	Message string `json:"message"`
	Status  int    `json:"-"`
}

func (e *Error) Error() string { return e.Code + ": " + e.Message }

func fail(status int, code, format string, a ...any) *Error {
	return &Error{Code: code, Message: fmt.Sprintf(format, a...), Status: status}
}

// Result is a verified request.
type Result struct {
	Agent   string
	KeyID   string
	Key     JWK
	Created time.Time
}

// Verifier checks Web Bot Auth signatures. Resolve returns the directory for
// an agent URL and must refuse agents it doesn't know (no open fetches).
type Verifier struct {
	Resolve func(ctx context.Context, agent string) (*Directory, error)
	MaxSkew time.Duration
	Nonces  *NonceStore
	Now     func() time.Time
}

// Verify runs the ordered checks: headers → digest → time + nonce → key → signature.
func (v *Verifier) Verify(r *http.Request) (*Result, error) {
	now := time.Now()
	if v.Now != nil {
		now = v.Now()
	}
	skew := v.MaxSkew
	if skew == 0 {
		skew = 60 * time.Second
	}

	input, sigHeader := r.Header.Get("Signature-Input"), r.Header.Get("Signature")
	if input == "" || sigHeader == "" {
		return nil, fail(401, "missing_signature", "send Signature, Signature-Input and Signature-Agent (Web Bot Auth)")
	}
	label, sp, err := pickSignature(input)
	if err != nil {
		return nil, fail(401, "bad_signature", "%v", err)
	}
	sig, err := dictBytes(sigHeader, label)
	if err != nil {
		return nil, fail(401, "bad_signature", "%v", err)
	}

	covered := map[string]bool{}
	for _, c := range sp.components {
		covered[c] = true
	}
	if !covered["@authority"] {
		return nil, fail(401, "bad_signature", "@authority must be covered")
	}
	agentHeader := r.Header.Get("Signature-Agent")
	if agentHeader == "" || !covered["signature-agent"] {
		return nil, fail(401, "bad_signature", "Signature-Agent must be sent and covered")
	}
	agent, err := parseAgent(agentHeader, label)
	if err != nil {
		return nil, fail(401, "bad_signature", "%v", err)
	}
	if alg, ok := sp.params["alg"]; ok && alg != "ed25519" {
		return nil, fail(401, "bad_signature", "alg %q not supported", alg)
	}

	if covered["content-digest"] {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			return nil, fail(400, "bad_request", "unreadable body")
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		if r.Header.Get("Content-Digest") != contentDigest(body) {
			return nil, fail(401, "digest_mismatch", "the body doesn't match Content-Digest")
		}
	} else if r.ContentLength > 0 {
		return nil, fail(401, "bad_signature", "a request body must be covered by content-digest")
	}

	created, err := strconv.ParseInt(sp.params["created"], 10, 64)
	if err != nil {
		return nil, fail(401, "bad_signature", "created is required")
	}
	ct := time.Unix(created, 0)
	if ct.After(now.Add(skew)) || ct.Before(now.Add(-skew)) {
		return nil, fail(401, "clock_skew", "created is %s from the server clock", now.Sub(ct).Round(time.Second))
	}
	if e, ok := sp.params["expires"]; ok {
		exp, err := strconv.ParseInt(e, 10, 64)
		if err != nil || now.After(time.Unix(exp, 0)) || exp-created > 300 {
			return nil, fail(401, "clock_skew", "signature expired")
		}
	}
	nonce := sp.params["nonce"]
	if nonce == "" {
		return nil, fail(401, "bad_signature", "nonce is required")
	}

	kid := sp.params["keyid"]
	dir, err := v.Resolve(r.Context(), agent)
	if err != nil {
		var we *Error
		if errors.As(err, &we) {
			return nil, we
		}
		return nil, fail(401, "unknown_key", "key directory for %s: %v", agent, err)
	}
	var key *JWK
	for i := range dir.Keys {
		if dir.Keys[i].Kid == kid {
			key = &dir.Keys[i]
		}
	}
	if key == nil {
		return nil, fail(401, "unknown_key", "keyid %s is not an active key of %s", kid, agent)
	}
	pub, err := key.PublicKey()
	if err != nil {
		return nil, fail(401, "unknown_key", "%v", err)
	}
	base, err := signatureBase(r, sp.components, sp.raw)
	if err != nil {
		return nil, fail(401, "bad_signature", "%v", err)
	}
	if !ed25519.Verify(pub, base, sig) {
		return nil, fail(401, "bad_signature", "the signature doesn't match the request")
	}
	if v.Nonces != nil && !v.Nonces.Add(agent+" "+nonce, now, 2*skew) {
		return nil, fail(401, "nonce_replayed", "this signature was already accepted once")
	}
	return &Result{Agent: agent, KeyID: kid, Key: *key, Created: ct}, nil
}

// AcceptSignature is the RFC 9421 §5.1 hint sent with 401s.
func AcceptSignature() string {
	return Label + `=("@method" "@authority" "@path" "signature-agent");keyid;created;expires;nonce;alg="ed25519";tag="web-bot-auth"`
}

// --- minimal structured-field parsing for the headers above ---

type sigParams struct {
	components []string
	params     map[string]string
	raw        string // the inner list + params exactly as received
}

// splitTop splits a dictionary on commas outside quotes and parentheses.
func splitTop(s string) []string {
	var out []string
	depth, inStr, start := 0, false, 0
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c == '\\' && inStr:
			i++
		case c == '"':
			inStr = !inStr
		case inStr:
		case c == '(':
			depth++
		case c == ')':
			depth--
		case c == ',' && depth == 0:
			out = append(out, strings.TrimSpace(s[start:i]))
			start = i + 1
		}
	}
	return append(out, strings.TrimSpace(s[start:]))
}

func parseParams(raw string) (*sigParams, error) {
	if !strings.HasPrefix(raw, "(") {
		return nil, errors.New("Signature-Input member is not an inner list")
	}
	end := strings.IndexByte(raw, ')')
	if end < 0 {
		return nil, errors.New("unterminated inner list")
	}
	sp := &sigParams{params: map[string]string{}, raw: raw}
	for _, item := range strings.Fields(raw[1:end]) {
		c, err := strconv.Unquote(item)
		if err != nil {
			return nil, fmt.Errorf("bad component %s", item)
		}
		sp.components = append(sp.components, c)
	}
	for _, p := range strings.Split(raw[end+1:], ";")[1:] {
		k, val, _ := strings.Cut(p, "=")
		if u, err := strconv.Unquote(val); err == nil {
			val = u
		}
		sp.params[strings.TrimSpace(k)] = val
	}
	return sp, nil
}

// pickSignature returns the Web Bot Auth member of Signature-Input.
func pickSignature(input string) (string, *sigParams, error) {
	for _, m := range splitTop(input) {
		label, raw, ok := strings.Cut(m, "=")
		if !ok {
			continue
		}
		sp, err := parseParams(raw)
		if err != nil {
			return "", nil, err
		}
		if sp.params["tag"] == Tag {
			return label, sp, nil
		}
	}
	return "", nil, errors.New(`no signature with tag="web-bot-auth"`)
}

func dictBytes(header, label string) ([]byte, error) {
	for _, m := range splitTop(header) {
		l, v, _ := strings.Cut(m, "=")
		if l == label && len(v) > 2 && v[0] == ':' && v[len(v)-1] == ':' {
			return base64.StdEncoding.DecodeString(v[1 : len(v)-1])
		}
	}
	return nil, fmt.Errorf("no Signature for label %s", label)
}

// parseAgent accepts both forms in the drafts: a string, or a dictionary keyed by label.
func parseAgent(header, label string) (string, error) {
	h := strings.TrimSpace(header)
	if strings.HasPrefix(h, `"`) {
		return strconv.Unquote(h)
	}
	for _, m := range splitTop(h) {
		if l, v, ok := strings.Cut(m, "="); ok && l == label {
			return strconv.Unquote(v)
		}
	}
	return "", errors.New("Signature-Agent has no value for " + label)
}

// NonceStore remembers nonces for replay protection (one instance, in memory).
type NonceStore struct {
	mu   sync.Mutex
	seen map[string]time.Time
}

func NewNonceStore() *NonceStore { return &NonceStore{seen: map[string]time.Time{}} }

// Add records a nonce and reports false if it was already seen.
func (n *NonceStore) Add(key string, now time.Time, ttl time.Duration) bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	for k, exp := range n.seen {
		if now.After(exp) {
			delete(n.seen, k)
		}
	}
	if _, dup := n.seen[key]; dup {
		return false
	}
	n.seen[key] = now.Add(ttl)
	return true
}

// SignatureBaseOf returns the RFC 9421 signature base a verifier rebuilds
// for a signed request (used to publish test vectors).
func SignatureBaseOf(r *http.Request) (string, error) {
	_, sp, err := pickSignature(r.Header.Get("Signature-Input"))
	if err != nil {
		return "", err
	}
	b, err := signatureBase(r, sp.components, sp.raw)
	return string(b), err
}
