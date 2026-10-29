// Package httpsig signs and verifies HTTP message signatures (RFC 9421) with
// Ed25519, for any request or response: any label, tag and key ID, every
// derived component, and every field parameter (sf, key, bs, req, tr).
//
//	m, _ := httpsig.NewRequest("POST", "https://example.com/foo", header, body)
//	s, _ := httpsig.Sign(m, signer, httpsig.SignOptions{Components: []string{"@method", "@authority", "content-digest"}, KeyID: "k1"})
//	s.AddTo(header)
//	v, err := httpsig.Verify(m, httpsig.VerifyOptions{Keys: myKeys})
//
// Web Bot Auth, built on this, is package messh (signing) and messh/verify.
package httpsig

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"messh.io/go/messh/internal/sf"
)

// Message is what a signature covers: a request, or a response with the
// request it answers.
type Message struct {
	Method        string      // request method, exactly as sent
	Scheme        string      // scheme of the target URI
	Authority     string      // host[:port]; lowercased when derived
	Path          string      // escaped path; empty means "/"
	Query         string      // raw query without "?"; empty means none
	RequestTarget string      // the request line's target, if known; else path and query
	Status        int         // response status code; 0 for a request
	Header        http.Header // header fields
	Trailer       http.Header // trailer fields, for components with tr
	Body          []byte      // checked against a covered Content-Digest; nil skips the check
	Request       *Message    // for a response: the request it answers, for components with req
}

// NewRequest describes a request to an absolute URL. A Host header, if set,
// is the authority.
func NewRequest(method, rawURL string, header http.Header, body []byte) (*Message, error) {
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("httpsig: %q is not an absolute URL", rawURL)
	}
	if header == nil {
		header = http.Header{}
	}
	m := &Message{Method: method, Scheme: u.Scheme, Authority: u.Host, Path: u.EscapedPath(), Query: u.RawQuery, Header: header, Body: body}
	if h := header.Get("Host"); h != "" {
		m.Authority = h
	}
	return m, nil
}

// FromRequest describes an incoming or outgoing *http.Request; body, if not
// nil, is checked against a covered Content-Digest.
func FromRequest(r *http.Request, body []byte) *Message {
	m := &Message{Method: r.Method, Scheme: r.URL.Scheme, Authority: r.Host, Path: r.URL.EscapedPath(), Query: r.URL.RawQuery,
		RequestTarget: r.RequestURI, Header: r.Header, Trailer: r.Trailer, Body: body}
	if m.Authority == "" {
		m.Authority = r.URL.Host
	}
	if m.Scheme == "" {
		m.Scheme = "http"
		if r.TLS != nil {
			m.Scheme = "https"
		}
	}
	return m
}

// Error is a signing or verification failure. Code is one of
// missing_signature, bad_signature, digest_mismatch, clock_skew,
// unknown_key, nonce_replayed (the codes messh's verifiers use).
type Error struct {
	Code    string `json:"error"`
	Message string `json:"message"`
	Status  int    `json:"-"`
}

func (e *Error) Error() string { return e.Code + ": " + e.Message }

func fail(code, format string, a ...any) *Error {
	return &Error{Code: code, Message: fmt.Sprintf(format, a...), Status: http.StatusUnauthorized}
}

// FieldTypes names the structured-field type ("dictionary", "list" or
// "item") of fields covered with sf. Common fields need no entry.
type FieldTypes map[string]string

var knownTypes = FieldTypes{
	"accept-signature": "dictionary", "cache-status": "list", "content-digest": "dictionary", "priority": "dictionary",
	"proxy-status": "list", "repr-digest": "dictionary", "signature": "dictionary", "signature-input": "dictionary",
	"signature-agent": "dictionary-or-item", "want-content-digest": "dictionary", "want-repr-digest": "dictionary",
}

// --- component identifiers ---

type component struct {
	name   string
	params sf.Params
}

func (c component) id() string { return sf.Str(c.name).String() + c.params.String() }

func (c component) item() sf.Item { return sf.Item{Bare: sf.Str(c.name), Params: c.params} }

var derivedName = regexp.MustCompile(`^@[a-z][a-z-]*$`)

func isToken(s string) bool {
	for i := 0; i < len(s); i++ {
		if c := s[i]; !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || strings.IndexByte("!#$%&'*+-.^_`|~", c) >= 0) {
			return false
		}
	}
	return s != ""
}

func checked(c component) (component, error) {
	if derivedName.MatchString(c.name) || isToken(c.name) {
		return c, nil
	}
	return c, fmt.Errorf("bad component name %q (lowercase field names, or @derived)", c.name)
}

// parseComponent reads a component as callers write it: a plain name
// (@method, Content-Type) or a serialized identifier ("example-dict";key="a").
func parseComponent(s string) (component, error) {
	if !strings.HasPrefix(s, `"`) {
		return checked(component{name: strings.ToLower(s)})
	}
	it, err := sf.ParseItem(s)
	if err != nil || it.Bare.Kind != sf.String {
		return component{}, fmt.Errorf("bad component identifier %s", s)
	}
	return checked(component{it.Bare.Str, it.Params})
}

// --- component values (RFC 9421 §2) ---

// Component returns the identifier and signature-base value of one component
// of m, as written in a signature base.
func Component(m *Message, comp string, types FieldTypes) (identifier, value string, err error) {
	c, err := parseComponent(comp)
	if err != nil {
		return "", "", err
	}
	v, err := m.value(c, types)
	return c.id(), v, err
}

func (m *Message) value(c component, types FieldTypes) (string, error) {
	var req, strict, bs, tr, hasKey, hasName bool
	var key, name string
	for _, p := range c.params {
		switch p.Key {
		case "req", "sf", "bs", "tr":
			if p.Value.Kind != sf.Boolean || !p.Value.Bool {
				return "", fmt.Errorf("%s: parameter %s must be true", c.id(), p.Key)
			}
			req, strict, bs, tr = req || p.Key == "req", strict || p.Key == "sf", bs || p.Key == "bs", tr || p.Key == "tr"
		case "key", "name":
			if p.Value.Kind != sf.String {
				return "", fmt.Errorf("%s: parameter %s must be a string", c.id(), p.Key)
			}
			if p.Key == "key" {
				key, hasKey = p.Value.Str, true
			} else {
				name, hasName = p.Value.Str, true
			}
		default:
			return "", fmt.Errorf("%s: unknown parameter %s", c.id(), p.Key)
		}
	}
	derived := strings.HasPrefix(c.name, "@")
	switch {
	case derived && (strict || bs || tr || hasKey):
		return "", fmt.Errorf("%s: sf, bs, tr and key apply to fields only", c.id())
	case hasName && c.name != "@query-param":
		return "", fmt.Errorf("%s: name applies to @query-param only", c.id())
	case bs && (strict || hasKey):
		return "", fmt.Errorf("%s: bs can't be combined with sf or key", c.id())
	}
	ctx := m
	if req {
		if m.Status == 0 || m.Request == nil {
			return "", fmt.Errorf("%s: req needs a response and the request it answers", c.id())
		}
		ctx = m.Request
	}
	if derived {
		if c.name == "@query-param" && !hasName {
			return "", errors.New("@query-param needs a name parameter")
		}
		return ctx.derived(c.name, name)
	}
	h := ctx.Header
	if tr {
		h = ctx.Trailer
	}
	return fieldValue(h, c.name, strict, bs, key, hasKey, types)
}

func (m *Message) path() string {
	if m.Path == "" {
		return "/"
	}
	return m.Path
}

func (m *Message) pathQuery() string {
	if m.Query == "" {
		return m.path()
	}
	return m.path() + "?" + m.Query
}

func (m *Message) derived(name, param string) (string, error) {
	if name == "@status" {
		if m.Status == 0 {
			return "", errors.New("@status applies to responses only")
		}
		return strconv.Itoa(m.Status), nil
	}
	if m.Authority == "" && m.Method == "" {
		return "", fmt.Errorf("%s needs the request (use req in a response signature)", name)
	}
	switch name {
	case "@method":
		if m.Method == "" {
			return "", errors.New("@method needs a request method")
		}
		return m.Method, nil
	case "@target-uri":
		if m.Scheme == "" || m.Authority == "" {
			return "", errors.New("@target-uri needs a scheme and an authority")
		}
		return strings.ToLower(m.Scheme) + "://" + strings.ToLower(m.Authority) + m.pathQuery(), nil
	case "@authority":
		if m.Authority == "" {
			return "", errors.New("@authority needs an authority")
		}
		return strings.ToLower(m.Authority), nil
	case "@scheme":
		if m.Scheme == "" {
			return "", errors.New("@scheme needs a scheme")
		}
		return strings.ToLower(m.Scheme), nil
	case "@request-target":
		if m.RequestTarget != "" {
			return m.RequestTarget, nil
		}
		return m.pathQuery(), nil
	case "@path":
		return m.path(), nil
	case "@query":
		return "?" + m.Query, nil
	case "@query-param":
		return queryParam(m.Query, param)
	}
	return "", fmt.Errorf("unknown derived component %s", name)
}

var obsFold = regexp.MustCompile(`[ \t]*\r?\n[ \t]+`)

func clean(v string) string { return obsFold.ReplaceAllString(strings.Trim(v, " \t"), " ") }

func fieldValue(h http.Header, name string, strict, bs bool, key string, hasKey bool, types FieldTypes) (string, error) {
	vals := h.Values(name)
	if len(vals) == 0 {
		return "", fmt.Errorf("covered field %s is missing", name)
	}
	parts := make([]string, len(vals))
	for i, v := range vals {
		parts[i] = clean(v)
		if bs {
			parts[i] = sf.Bytes([]byte(parts[i])).String()
		}
	}
	v := strings.Join(parts, ", ")
	switch {
	case hasKey:
		d, _, err := sf.ParseDictionary(v)
		if err != nil {
			return "", fmt.Errorf("%s is not a dictionary: %v", name, err)
		}
		m, ok := d.Get(key)
		if !ok {
			return "", fmt.Errorf("%s has no member %q", name, key)
		}
		return m.String(), nil
	case strict:
		return strictValue(name, v, types)
	}
	return v, nil
}

func strictValue(name, v string, types FieldTypes) (string, error) {
	t := types[name]
	if t == "" {
		t = knownTypes[name]
	}
	switch t {
	case "dictionary", "dictionary-or-item":
		d, _, err := sf.ParseDictionary(v)
		if err == nil {
			return d.String(), nil
		}
		if t == "dictionary" {
			return "", fmt.Errorf("%s: %v", name, err)
		}
		fallthrough
	case "item":
		it, err := sf.ParseItem(v)
		if err != nil {
			return "", fmt.Errorf("%s: %v", name, err)
		}
		return it.String(), nil
	case "list":
		l, err := sf.ParseList(v)
		if err != nil {
			return "", fmt.Errorf("%s: %v", name, err)
		}
		return sf.SerializeList(l), nil
	}
	return "", fmt.Errorf("can't serialize %s strictly: its structured-field type is unknown", name)
}

// queryParam is the encoded value of one query parameter (RFC 9421 §2.2.8).
func queryParam(raw, name string) (string, error) {
	var vals []string
	for _, part := range strings.Split(raw, "&") {
		if part == "" {
			continue
		}
		k, v, _ := strings.Cut(part, "=")
		if formEncode(formDecode(k)) == name {
			vals = append(vals, formEncode(formDecode(v)))
		}
	}
	switch len(vals) {
	case 0:
		return "", fmt.Errorf("query parameter %q is missing", name)
	case 1:
		return vals[0], nil
	}
	return "", fmt.Errorf("query parameter %q occurs more than once", name)
}

func unhex(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

// formDecode is application/x-www-form-urlencoded parsing of one name or value.
func formDecode(s string) []byte {
	s = strings.ReplaceAll(s, "+", " ")
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+2 < len(s) {
			hi, ok1 := unhex(s[i+1])
			lo, ok2 := unhex(s[i+2])
			if ok1 && ok2 {
				out = append(out, hi<<4|lo)
				i += 2
				continue
			}
		}
		out = append(out, s[i])
	}
	return out
}

// formEncode percent-encodes everything but ASCII alphanumerics and *-._, with
// space as %20 (RFC 9421 §2.2.8).
func formEncode(b []byte) string {
	var sb strings.Builder
	for _, c := range b {
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.IndexByte("*-._", c) >= 0 {
			sb.WriteByte(c)
		} else {
			fmt.Fprintf(&sb, "%%%02X", c)
		}
	}
	return sb.String()
}

// --- signature base (RFC 9421 §2.5) ---

func (m *Message) base(comps []component, params string, types FieldTypes) (string, error) {
	var b strings.Builder
	seen := map[string]bool{}
	for _, c := range comps {
		id := c.id()
		if seen[id] {
			return "", fmt.Errorf("component %s is covered twice", id)
		}
		seen[id] = true
		v, err := m.value(c, types)
		if err != nil {
			return "", err
		}
		b.WriteString(id + ": " + v + "\n")
	}
	b.WriteString(`"@signature-params": ` + params)
	s := b.String()
	for i := 0; i < len(s); i++ {
		if s[i] > 0x7e || (s[i] < 0x20 && s[i] != '\n') {
			return "", errors.New("signature base must be printable ASCII (wrap such fields with bs)")
		}
	}
	return s, nil
}

// --- signing ---

// Signer signs with an Ed25519 key. messh.Signer values satisfy it.
type Signer interface {
	Public() ed25519.PublicKey
	Sign(data []byte) ([]byte, error)
}

// SignOptions describes one signature. Zero or empty parameters are left out.
type SignOptions struct {
	Label      string   // default "sig1"
	Components []string // covered components, in order
	Created    time.Time
	Expires    time.Time
	KeyID      string
	Alg        string // "ed25519", or empty to leave it out
	Nonce      string
	Tag        string
	FieldTypes FieldTypes // types of fields covered with sf
}

// Signed is a signature ready to send.
type Signed struct {
	Label     string
	Input     string // the Signature-Input member value: covered components and parameters
	Signature string // the Signature member value: :base64:
	Base      string // the signature base that was signed
}

// AddTo adds the signature to h's Signature-Input and Signature fields,
// after any signatures already there.
func (s *Signed) AddTo(h http.Header) {
	for name, v := range map[string]string{"Signature-Input": s.Input, "Signature": s.Signature} {
		vals := append(h.Values(name), s.Label+"="+v)
		h.Set(name, strings.Join(vals, ", "))
	}
}

// Sign signs m. Components are plain names (@method, content-type) or
// serialized identifiers with parameters ("example-dict";key="a").
func Sign(m *Message, signer Signer, o SignOptions) (*Signed, error) {
	label := o.Label
	if label == "" {
		label = "sig1"
	}
	if !sf.ValidKey(label) {
		return nil, fmt.Errorf("httpsig: bad label %q", label)
	}
	comps := make([]component, len(o.Components))
	items := make([]sf.Item, len(o.Components))
	for i, s := range o.Components {
		c, err := parseComponent(s)
		if err != nil {
			return nil, fmt.Errorf("httpsig: %w", err)
		}
		comps[i], items[i] = c, c.item()
	}
	var params sf.Params
	if !o.Created.IsZero() {
		params = append(params, sf.Param{Key: "created", Value: sf.Int(o.Created.Unix())})
	}
	if !o.Expires.IsZero() {
		params = append(params, sf.Param{Key: "expires", Value: sf.Int(o.Expires.Unix())})
	}
	for _, p := range [][2]string{{"keyid", o.KeyID}, {"alg", o.Alg}, {"nonce", o.Nonce}, {"tag", o.Tag}} {
		if p[1] == "" {
			continue
		}
		if !sf.ValidString(p[1]) {
			return nil, fmt.Errorf("httpsig: %s must be printable ASCII", p[0])
		}
		params = append(params, sf.Param{Key: p[0], Value: sf.Str(p[1])})
	}
	input := sf.Member{Inner: true, Items: items, Params: params}.String()
	base, err := m.base(comps, input, o.FieldTypes)
	if err != nil {
		return nil, fmt.Errorf("httpsig: %w", err)
	}
	sig, err := signer.Sign([]byte(base))
	if err != nil {
		return nil, fmt.Errorf("httpsig: sign: %w", err)
	}
	return &Signed{Label: label, Input: input, Signature: sf.Bytes(sig).String(), Base: base}, nil
}

// --- parsing signatures ---

// Covered is one covered component of a signature.
type Covered struct {
	ID   string // serialized identifier, e.g. `"signature-agent";key="sig1"`
	Name string // component name, e.g. "signature-agent"
	Key  string // its key parameter, if any
}

// Signature is one signature of a message, parsed but not verified.
type Signature struct {
	Label   string
	Covered []Covered
	Created int64 // 0 when absent
	Expires int64 // 0 when absent
	KeyID   string
	Alg     string
	Nonce   string
	Tag     string
	Value   []byte

	comps  []component
	params string // the signature parameters, strictly serialized
}

// Covers reports whether a component with this name is covered, with any parameters.
func (s *Signature) Covers(name string) bool {
	for _, c := range s.Covered {
		if c.Name == name {
			return true
		}
	}
	return false
}

func dictionary(h http.Header, name string) (sf.Dictionary, error) {
	d, dups, err := sf.ParseDictionary(strings.Join(h.Values(name), ", "))
	if err != nil {
		return nil, fail("bad_signature", "%s: %v", name, err)
	}
	if len(dups) > 0 {
		return nil, fail("bad_signature", "%s repeats the label %s", name, dups[0])
	}
	return d, nil
}

// Signatures parses m's Signature-Input and Signature fields. Labels and
// covered components must not repeat (RFC 9421 §4.1, §2.5).
func Signatures(m *Message) ([]*Signature, error) {
	if len(m.Header.Values("Signature-Input")) == 0 || len(m.Header.Values("Signature")) == 0 {
		return nil, fail("missing_signature", "send Signature-Input and Signature (RFC 9421)")
	}
	inputs, err := dictionary(m.Header, "Signature-Input")
	if err != nil {
		return nil, err
	}
	sigs, err := dictionary(m.Header, "Signature")
	if err != nil {
		return nil, err
	}
	var out []*Signature
	for _, e := range inputs {
		if !e.Member.Inner {
			return nil, fail("bad_signature", "Signature-Input %s is not an inner list", e.Key)
		}
		s := &Signature{Label: e.Key, params: e.Member.String()}
		seen := map[string]bool{}
		for _, it := range e.Member.Items {
			if it.Bare.Kind != sf.String {
				return nil, fail("bad_signature", "Signature-Input %s: component %s is not a string", e.Key, it)
			}
			c, err := checked(component{it.Bare.Str, it.Params})
			if err != nil {
				return nil, fail("bad_signature", "Signature-Input %s: %v", e.Key, err)
			}
			if seen[c.id()] {
				return nil, fail("bad_signature", "Signature-Input %s covers %s twice", e.Key, c.id())
			}
			seen[c.id()] = true
			cov := Covered{ID: c.id(), Name: c.name}
			if k, ok := c.params.Get("key"); ok && k.Kind == sf.String {
				cov.Key = k.Str
			}
			s.comps, s.Covered = append(s.comps, c), append(s.Covered, cov)
		}
		for _, p := range e.Member.Params {
			switch p.Key {
			case "created", "expires":
				if p.Value.Kind != sf.Integer {
					return nil, fail("bad_signature", "%s must be an integer", p.Key)
				}
				if p.Key == "created" {
					s.Created = p.Value.Int
				} else {
					s.Expires = p.Value.Int
				}
			case "keyid", "alg", "nonce", "tag":
				if p.Value.Kind != sf.String {
					return nil, fail("bad_signature", "%s must be a string", p.Key)
				}
				switch p.Key {
				case "keyid":
					s.KeyID = p.Value.Str
				case "alg":
					s.Alg = p.Value.Str
				case "nonce":
					s.Nonce = p.Value.Str
				default:
					s.Tag = p.Value.Str
				}
			}
		}
		if v, ok := sigs.Get(e.Key); ok && !v.Inner && v.Bare.Kind == sf.ByteSeq {
			s.Value = v.Bare.Bytes
		} else {
			return nil, fail("bad_signature", "no Signature for %s", e.Key)
		}
		out = append(out, s)
	}
	if len(out) == 0 {
		return nil, fail("missing_signature", "Signature-Input has no signatures")
	}
	return out, nil
}

// Pick chooses a signature by label, else by tag, else the only one.
func Pick(sigs []*Signature, label, tag string) (*Signature, error) {
	for _, s := range sigs {
		if (label != "" && s.Label == label) || (label == "" && tag != "" && s.Tag == tag) {
			return s, nil
		}
	}
	switch {
	case label != "":
		return nil, fail("bad_signature", "no signature labeled %s", label)
	case tag != "":
		return nil, fail("bad_signature", "no signature with tag=%q", tag)
	case len(sigs) == 1:
		return sigs[0], nil
	}
	return nil, fail("bad_signature", "the message has %d signatures: choose one by label or tag", len(sigs))
}

// ContentDigest is the RFC 9530 Content-Digest field for body (sha-256).
func ContentDigest(body []byte) string {
	h := sha256.Sum256(body)
	return "sha-256=" + sf.Bytes(h[:]).String()
}

// CheckDigest checks body against a Content-Digest field (sha-256 or sha-512).
func CheckDigest(field string, body []byte) error {
	d, _, err := sf.ParseDictionary(field)
	known := 0
	if err == nil {
		for _, e := range d {
			var sum []byte
			switch e.Key {
			case "sha-256":
				h := sha256.Sum256(body)
				sum = h[:]
			case "sha-512":
				h := sha512.Sum512(body)
				sum = h[:]
			default:
				continue
			}
			known++
			if e.Member.Inner || e.Member.Bare.Kind != sf.ByteSeq || string(e.Member.Bare.Bytes) != string(sum) {
				return fail("digest_mismatch", "the body doesn't match Content-Digest")
			}
		}
	}
	if known == 0 {
		return fail("digest_mismatch", "Content-Digest has no sha-256 or sha-512 digest")
	}
	return nil
}

// --- verifying ---

// NonceStore remembers nonces for replay protection; Add returns false if
// key was already seen within ttl.
type NonceStore interface {
	Add(key string, ttl time.Duration) bool
}

// VerifyOptions say which signature to verify and how.
type VerifyOptions struct {
	Label      string                                        // verify the signature with this label
	Tag        string                                        // or the first one with this tag (else the only one)
	Keys       func(keyID string) (ed25519.PublicKey, error) // required; an error means unknown_key
	Now        func() time.Time                              // default time.Now
	MaxSkew    time.Duration                                 // how far created may be ahead of now; default 60s
	MaxAge     time.Duration                                 // if set, how old created may be
	Required   []string                                      // component names that must be covered
	Nonces     NonceStore                                    // reject a nonce seen before (signatures with a nonce)
	FieldTypes FieldTypes
}

// Verified is a verified signature.
type Verified struct {
	Label      string
	Components []string // covered component identifiers
	KeyID      string
	Alg        string
	Nonce      string
	Tag        string
	Created    time.Time // zero when absent
	Expires    time.Time // zero when absent
	Base       string
}

// Verify checks one signature of m: content digest, time, key, then the
// signature itself. Errors are *Error.
func Verify(m *Message, o VerifyOptions) (*Verified, error) {
	sigs, err := Signatures(m)
	if err != nil {
		return nil, err
	}
	s, err := Pick(sigs, o.Label, o.Tag)
	if err != nil {
		return nil, err
	}
	return VerifySignature(m, s, o)
}

// VerifySignature checks a signature from Signatures; o.Label and o.Tag are ignored.
func VerifySignature(m *Message, s *Signature, o VerifyOptions) (*Verified, error) {
	for _, name := range o.Required {
		if !s.Covers(name) {
			return nil, fail("bad_signature", "%s must be covered", name)
		}
	}
	if s.Alg != "" && s.Alg != "ed25519" {
		return nil, fail("bad_signature", "alg %q is not supported (ed25519 only)", s.Alg)
	}
	for _, c := range s.comps {
		if c.name != "content-digest" {
			continue
		}
		ctx := m
		if _, req := c.params.Get("req"); req && m.Request != nil {
			ctx = m.Request
		}
		if ctx.Body != nil {
			if err := CheckDigest(strings.Join(ctx.Header.Values("Content-Digest"), ", "), ctx.Body); err != nil {
				return nil, err
			}
		}
	}
	now := time.Now()
	if o.Now != nil {
		now = o.Now()
	}
	skew := o.MaxSkew
	if skew == 0 {
		skew = 60 * time.Second
	}
	if s.Created != 0 {
		created := time.Unix(s.Created, 0)
		if created.After(now.Add(skew)) {
			return nil, fail("clock_skew", "created is %s ahead of the clock", created.Sub(now).Round(time.Second))
		}
		if o.MaxAge > 0 && created.Before(now.Add(-o.MaxAge)) {
			return nil, fail("clock_skew", "the signature is %s old", now.Sub(created).Round(time.Second))
		}
	}
	if s.Expires != 0 && now.After(time.Unix(s.Expires, 0)) {
		return nil, fail("clock_skew", "the signature expired")
	}
	if o.Keys == nil {
		return nil, fail("unknown_key", "no key resolver configured")
	}
	pub, err := o.Keys(s.KeyID)
	if err != nil {
		var he *Error
		if errors.As(err, &he) {
			return nil, he
		}
		return nil, fail("unknown_key", "keyid %q: %v", s.KeyID, err)
	}
	if len(pub) != ed25519.PublicKeySize {
		return nil, fail("unknown_key", "keyid %q is not an Ed25519 key", s.KeyID)
	}
	base, err := m.base(s.comps, s.params, o.FieldTypes)
	if err != nil {
		return nil, fail("bad_signature", "%v", err)
	}
	if !ed25519.Verify(pub, []byte(base), s.Value) {
		return nil, fail("bad_signature", "the signature doesn't match the message")
	}
	if o.Nonces != nil && s.Nonce != "" {
		ttl := 2 * skew
		if o.MaxAge > 0 {
			ttl = o.MaxAge + skew
		}
		if s.Expires != 0 {
			if d := time.Unix(s.Expires, 0).Sub(now) + skew; d > ttl {
				ttl = d
			}
		}
		if !o.Nonces.Add(s.KeyID+" "+s.Nonce, ttl) {
			return nil, fail("nonce_replayed", "this signature was already accepted once")
		}
	}
	v := &Verified{Label: s.Label, KeyID: s.KeyID, Alg: s.Alg, Nonce: s.Nonce, Tag: s.Tag, Base: base}
	for _, c := range s.Covered {
		v.Components = append(v.Components, c.ID)
	}
	if s.Created != 0 {
		v.Created = time.Unix(s.Created, 0)
	}
	if s.Expires != 0 {
		v.Expires = time.Unix(s.Expires, 0)
	}
	return v, nil
}

// DecodeKey decodes a base64url Ed25519 public key (a JWK's x).
func DecodeKey(x string) (ed25519.PublicKey, error) {
	b, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(x, "="))
	if err != nil || len(b) != ed25519.PublicKeySize {
		return nil, errors.New("not an Ed25519 public key")
	}
	return b, nil
}
