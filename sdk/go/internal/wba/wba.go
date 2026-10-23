// Package wba holds the Web Bot Auth wire format shared by the client and
// the verifier: RFC 9421 signature base, structured-field parsing, RFC 7638
// thumbprints and RFC 9530 Content-Digest.
package wba

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

const (
	Tag           = "web-bot-auth"
	Label         = "sig1"
	DirectoryPath = "/.well-known/http-message-signatures-directory"
	MaxLifetime   = 300 // seconds
)

// JWK is an Ed25519 public key in a key directory.
type JWK struct {
	Kty         string `json:"kty"`
	Crv         string `json:"crv"`
	X           string `json:"x"`
	Kid         string `json:"kid,omitempty"`
	Name        string `json:"messh_name,omitempty"`
	Fingerprint string `json:"messh_fingerprint,omitempty"`
}

// Directory is the body of <agent>/.well-known/http-message-signatures-directory.
type Directory struct {
	Keys []JWK `json:"keys"`
}

// Thumbprint is the RFC 7638 JWK thumbprint of an Ed25519 public key.
func Thumbprint(pub ed25519.PublicKey) string {
	h := sha256.Sum256([]byte(`{"crv":"Ed25519","kty":"OKP","x":"` + base64.RawURLEncoding.EncodeToString(pub) + `"}`))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

// PublicKey decodes the JWK and checks that kid, if set, is its thumbprint.
func (k JWK) PublicKey() (ed25519.PublicKey, error) {
	b, err := base64.RawURLEncoding.DecodeString(k.X)
	if err != nil || k.Kty != "OKP" || k.Crv != "Ed25519" || len(b) != ed25519.PublicKeySize {
		return nil, errors.New("not an Ed25519 JWK")
	}
	if k.Kid != "" && k.Kid != Thumbprint(b) {
		return nil, errors.New("JWK kid is not its thumbprint")
	}
	return b, nil
}

// SSHString is the SSH wire-format string: uint32 length, then the bytes.
func SSHString(b []byte) []byte {
	out := make([]byte, 4, 4+len(b))
	binary.BigEndian.PutUint32(out, uint32(len(b)))
	return append(out, b...)
}

// Fingerprint is the key's SSH fingerprint, as ssh-keygen -l and messh print it: SHA256:…
func Fingerprint(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(append(SSHString([]byte("ssh-ed25519")), SSHString(pub)...))
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])
}

func ContentDigest(body []byte) string {
	h := sha256.Sum256(body)
	return "sha-256=:" + base64.StdEncoding.EncodeToString(h[:]) + ":"
}

// Component is one covered component and its value.
type Component struct{ Name, Value string }

// Params serializes the signature parameters exactly as messh clients send them.
func Params(names []string, created, expires int64, keyid, nonce string) string {
	q := make([]string, len(names))
	for i, n := range names {
		q[i] = strconv.Quote(n)
	}
	return fmt.Sprintf(`(%s);created=%d;expires=%d;keyid=%q;alg="ed25519";nonce=%q;tag=%q`,
		strings.Join(q, " "), created, expires, keyid, nonce, Tag)
}

// Base is the RFC 9421 §2.5 signature base.
func Base(components []Component, params string) []byte {
	var b strings.Builder
	for _, c := range components {
		fmt.Fprintf(&b, "%q: %s\n", c.Name, c.Value)
	}
	b.WriteString(`"@signature-params": ` + params)
	return []byte(b.String())
}

// SigParams is one parsed Signature-Input member.
type SigParams struct {
	Label      string
	Components []string
	Params     map[string]string
	Raw        string // inner list + parameters exactly as received
}

func (s *SigParams) Covers(name string) bool {
	for _, c := range s.Components {
		if c == name {
			return true
		}
	}
	return false
}

// splitTop splits a structured-field dictionary on top-level commas.
func splitTop(s string) []string {
	var out []string
	depth, inStr, start := 0, false, 0
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case inStr && c == '\\':
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

func parseMember(label, raw string) (*SigParams, error) {
	if !strings.HasPrefix(raw, "(") {
		return nil, errors.New("Signature-Input member is not an inner list")
	}
	end := strings.IndexByte(raw, ')')
	if end < 0 {
		return nil, errors.New("unterminated inner list")
	}
	sp := &SigParams{Label: label, Params: map[string]string{}, Raw: raw}
	for _, item := range strings.Fields(raw[1:end]) {
		c, err := strconv.Unquote(item)
		if err != nil {
			return nil, fmt.Errorf("bad component %s", item)
		}
		sp.Components = append(sp.Components, c)
	}
	for _, p := range strings.Split(raw[end+1:], ";")[1:] {
		k, v, _ := strings.Cut(p, "=")
		if u, err := strconv.Unquote(v); err == nil {
			v = u
		}
		sp.Params[strings.TrimSpace(k)] = v
	}
	return sp, nil
}

// PickWebBotAuth returns the Signature-Input member tagged web-bot-auth.
func PickWebBotAuth(input string) (*SigParams, error) {
	for _, m := range splitTop(input) {
		label, raw, ok := strings.Cut(m, "=")
		if !ok {
			continue
		}
		sp, err := parseMember(label, raw)
		if err != nil {
			return nil, err
		}
		if sp.Params["tag"] == Tag {
			return sp, nil
		}
	}
	return nil, errors.New(`no signature with tag="web-bot-auth"`)
}

// SignatureBytes returns the byte sequence for label in a Signature header.
func SignatureBytes(header, label string) ([]byte, error) {
	for _, m := range splitTop(header) {
		l, v, _ := strings.Cut(m, "=")
		if l == label && len(v) > 2 && v[0] == ':' && v[len(v)-1] == ':' {
			return base64.StdEncoding.DecodeString(v[1 : len(v)-1])
		}
	}
	return nil, fmt.Errorf("no Signature for %s", label)
}

// ParseAgent reads Signature-Agent as a string or as a dictionary keyed by label.
func ParseAgent(header, label string) (string, error) {
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
