// Package sf parses and serializes HTTP Structured Field Values (RFC 8941):
// Signature-Input, Signature and Signature-Agent, component identifiers, and
// fields covered with the sf or key parameters.
package sf

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// Kind is the type of a bare item.
type Kind int

const (
	Integer Kind = iota
	Decimal
	String
	Token
	ByteSeq
	Boolean
)

// Bare is a bare item. A Decimal is stored in thousandths, so serializing it
// never depends on floating point.
type Bare struct {
	Kind  Kind
	Int   int64
	Str   string
	Bytes []byte
	Bool  bool
}

func Str(s string) Bare   { return Bare{Kind: String, Str: s} }
func Tok(s string) Bare   { return Bare{Kind: Token, Str: s} }
func Int(n int64) Bare    { return Bare{Kind: Integer, Int: n} }
func Bytes(b []byte) Bare { return Bare{Kind: ByteSeq, Bytes: b} }
func True() Bare          { return Bare{Kind: Boolean, Bool: true} }

// Param is one parameter. Params keeps their order; keys are unique.
type Param struct {
	Key   string
	Value Bare
}

type Params []Param

// Get returns the value of key.
func (ps Params) Get(key string) (Bare, bool) {
	for _, p := range ps {
		if p.Key == key {
			return p.Value, true
		}
	}
	return Bare{}, false
}

func (ps Params) set(key string, v Bare) Params {
	for i := range ps {
		if ps[i].Key == key {
			ps[i].Value = v
			return ps
		}
	}
	return append(ps, Param{key, v})
}

// Item is a bare item with parameters.
type Item struct {
	Bare   Bare
	Params Params
}

// Member is a list or dictionary member: an Item, or an Inner List.
type Member struct {
	Inner  bool
	Bare   Bare   // the item's value (not Inner)
	Items  []Item // the inner list (Inner)
	Params Params // the item's or the inner list's parameters
}

// Entry is one dictionary member.
type Entry struct {
	Key    string
	Member Member
}

// Dictionary keeps member order; keys are unique (a repeated key keeps its
// first position and its last value, RFC 8941 §4.2.2).
type Dictionary []Entry

// Get returns the member for key.
func (d Dictionary) Get(key string) (Member, bool) {
	for _, e := range d {
		if e.Key == key {
			return e.Member, true
		}
	}
	return Member{}, false
}

// --- parsing (RFC 8941 §4.2) ---

type parser struct {
	s string
	i int
}

func newParser(s string) (*parser, error) {
	for i := 0; i < len(s); i++ {
		if s[i] > 0x7f {
			return nil, errors.New("structured field is not ASCII")
		}
	}
	p := &parser{s: s}
	p.skip(" ")
	return p, nil
}

func (p *parser) eof() bool  { return p.i >= len(p.s) }
func (p *parser) peek() byte { return p.s[p.i] }

func (p *parser) skip(chars string) {
	for !p.eof() && strings.IndexByte(chars, p.peek()) >= 0 {
		p.i++
	}
}

func (p *parser) end() error {
	p.skip(" ")
	if !p.eof() {
		return fmt.Errorf("unexpected %q at %d", p.peek(), p.i)
	}
	return nil
}

func fail(format string, a ...any) error { return fmt.Errorf("structured field: "+format, a...) }

// ParseItem parses an Item field.
func ParseItem(s string) (Item, error) {
	p, err := newParser(s)
	if err != nil {
		return Item{}, err
	}
	it, err := p.item()
	if err != nil {
		return Item{}, err
	}
	return it, p.end()
}

// ParseList parses a List field.
func ParseList(s string) ([]Member, error) {
	p, err := newParser(s)
	if err != nil {
		return nil, err
	}
	var out []Member
	for !p.eof() {
		m, err := p.member()
		if err != nil {
			return nil, err
		}
		out = append(out, m)
		if done, err := p.next(); done || err != nil {
			return out, err
		}
	}
	return out, nil
}

// ParseDictionary parses a Dictionary field. duplicates lists keys that
// occurred more than once (callers such as Signature-Input must reject them).
func ParseDictionary(s string) (d Dictionary, duplicates []string, err error) {
	p, err := newParser(s)
	if err != nil {
		return nil, nil, err
	}
	for !p.eof() {
		key, err := p.key()
		if err != nil {
			return nil, nil, err
		}
		var m Member
		if !p.eof() && p.peek() == '=' {
			p.i++
			if m, err = p.member(); err != nil {
				return nil, nil, err
			}
		} else {
			params, err := p.params()
			if err != nil {
				return nil, nil, err
			}
			m = Member{Bare: True(), Params: params}
		}
		replaced := false
		for i := range d {
			if d[i].Key == key {
				d[i].Member, replaced = m, true
				duplicates = append(duplicates, key)
			}
		}
		if !replaced {
			d = append(d, Entry{key, m})
		}
		if done, err := p.next(); done || err != nil {
			return d, duplicates, err
		}
	}
	return d, duplicates, nil
}

// next moves past the comma between members; done is true at the end.
func (p *parser) next() (done bool, err error) {
	p.skip(" \t")
	if p.eof() {
		return true, nil
	}
	if p.peek() != ',' {
		return false, fail("expected a comma at %d", p.i)
	}
	p.i++
	p.skip(" \t")
	if p.eof() {
		return false, fail("trailing comma")
	}
	return false, nil
}

func (p *parser) member() (Member, error) {
	if !p.eof() && p.peek() == '(' {
		return p.innerList()
	}
	it, err := p.item()
	return Member{Bare: it.Bare, Params: it.Params}, err
}

func (p *parser) innerList() (Member, error) {
	p.i++ // (
	m := Member{Inner: true, Items: []Item{}}
	for !p.eof() {
		p.skip(" ")
		if p.eof() {
			break
		}
		if p.peek() == ')' {
			p.i++
			params, err := p.params()
			m.Params = params
			return m, err
		}
		it, err := p.item()
		if err != nil {
			return m, err
		}
		m.Items = append(m.Items, it)
		if !p.eof() && p.peek() != ' ' && p.peek() != ')' {
			return m, fail("expected a space or ) at %d", p.i)
		}
	}
	return m, fail("unterminated inner list")
}

func (p *parser) item() (Item, error) {
	b, err := p.bare()
	if err != nil {
		return Item{}, err
	}
	params, err := p.params()
	return Item{b, params}, err
}

func (p *parser) params() (Params, error) {
	var ps Params
	for !p.eof() && p.peek() == ';' {
		p.i++
		p.skip(" ")
		key, err := p.key()
		if err != nil {
			return nil, err
		}
		v := True()
		if !p.eof() && p.peek() == '=' {
			p.i++
			if v, err = p.bare(); err != nil {
				return nil, err
			}
		}
		ps = ps.set(key, v)
	}
	return ps, nil
}

func isLCAlpha(c byte) bool { return c >= 'a' && c <= 'z' }
func isAlpha(c byte) bool   { return isLCAlpha(c) || (c >= 'A' && c <= 'Z') }
func isDigit(c byte) bool   { return c >= '0' && c <= '9' }
func isTChar(c byte) bool {
	return isAlpha(c) || isDigit(c) || strings.IndexByte("!#$%&'*+-.^_`|~", c) >= 0
}

func (p *parser) key() (string, error) {
	if p.eof() || !(isLCAlpha(p.peek()) || p.peek() == '*') {
		return "", fail("expected a key at %d", p.i)
	}
	start := p.i
	for !p.eof() {
		c := p.peek()
		if !(isLCAlpha(c) || isDigit(c) || strings.IndexByte("_-.*", c) >= 0) {
			break
		}
		p.i++
	}
	return p.s[start:p.i], nil
}

func (p *parser) bare() (Bare, error) {
	if p.eof() {
		return Bare{}, fail("expected an item")
	}
	switch c := p.peek(); {
	case c == '-' || isDigit(c):
		return p.number()
	case c == '"':
		return p.str()
	case c == '*' || isAlpha(c):
		return p.token(), nil
	case c == ':':
		return p.bytes()
	case c == '?':
		if p.i+1 < len(p.s) && (p.s[p.i+1] == '0' || p.s[p.i+1] == '1') {
			p.i += 2
			return Bare{Kind: Boolean, Bool: p.s[p.i-1] == '1'}, nil
		}
		return Bare{}, fail("bad boolean at %d", p.i)
	}
	return Bare{}, fail("unexpected %q at %d", p.peek(), p.i)
}

func (p *parser) number() (Bare, error) {
	neg := false
	if p.peek() == '-' {
		neg = true
		p.i++
	}
	if p.eof() || !isDigit(p.peek()) {
		return Bare{}, fail("expected a digit at %d", p.i)
	}
	start, dot := p.i, -1
	for !p.eof() {
		c := p.peek()
		if isDigit(c) {
			p.i++
		} else if c == '.' && dot < 0 {
			if p.i-start > 12 {
				return Bare{}, fail("decimal has too many integer digits")
			}
			dot = p.i
			p.i++
		} else {
			break
		}
		if dot < 0 && p.i-start > 15 {
			return Bare{}, fail("integer has too many digits")
		}
		if dot >= 0 && p.i-start > 16 {
			return Bare{}, fail("decimal has too many digits")
		}
	}
	num := p.s[start:p.i]
	if dot < 0 {
		n, _ := strconv.ParseInt(num, 10, 64)
		if neg {
			n = -n
		}
		return Int(n), nil
	}
	whole, frac := num[:dot-start], num[dot-start+1:]
	if frac == "" || len(frac) > 3 {
		return Bare{}, fail("decimal needs 1 to 3 fractional digits")
	}
	w, _ := strconv.ParseInt(whole, 10, 64)
	f, _ := strconv.ParseInt((frac + "00")[:3], 10, 64)
	n := w*1000 + f
	if neg {
		n = -n
	}
	return Bare{Kind: Decimal, Int: n}, nil
}

func (p *parser) str() (Bare, error) {
	p.i++ // "
	var b strings.Builder
	for !p.eof() {
		c := p.peek()
		p.i++
		switch {
		case c == '\\':
			if p.eof() || (p.peek() != '"' && p.peek() != '\\') {
				return Bare{}, fail("bad escape in string")
			}
			b.WriteByte(p.peek())
			p.i++
		case c == '"':
			return Str(b.String()), nil
		case c < 0x20 || c == 0x7f:
			return Bare{}, fail("control character in string")
		default:
			b.WriteByte(c)
		}
	}
	return Bare{}, fail("unterminated string")
}

func (p *parser) token() Bare {
	start := p.i
	p.i++
	for !p.eof() && (isTChar(p.peek()) || p.peek() == ':' || p.peek() == '/') {
		p.i++
	}
	return Tok(p.s[start:p.i])
}

func (p *parser) bytes() (Bare, error) {
	p.i++ // :
	end := strings.IndexByte(p.s[p.i:], ':')
	if end < 0 {
		return Bare{}, fail("unterminated byte sequence")
	}
	content := p.s[p.i : p.i+end]
	p.i += end + 1
	for i := 0; i < len(content); i++ {
		if c := content[i]; !(isAlpha(c) || isDigit(c) || c == '+' || c == '/' || c == '=') {
			return Bare{}, fail("bad base64 in byte sequence")
		}
	}
	b, err := base64.RawStdEncoding.DecodeString(strings.TrimRight(content, "="))
	if err != nil {
		return Bare{}, fail("bad base64 in byte sequence")
	}
	return Bytes(b), nil
}

// --- serializing (RFC 8941 §4.1) ---

// ValidKey reports whether s can be a dictionary or parameter key.
func ValidKey(s string) bool {
	p := &parser{s: s}
	k, err := p.key()
	return err == nil && k == s
}

// ValidString reports whether s can be serialized as a String.
func ValidString(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

func (b Bare) String() string {
	switch b.Kind {
	case Integer:
		return strconv.FormatInt(b.Int, 10)
	case Decimal:
		n, sign := b.Int, ""
		if n < 0 {
			n, sign = -n, "-"
		}
		frac := strings.TrimRight(fmt.Sprintf("%03d", n%1000), "0")
		if frac == "" {
			frac = "0"
		}
		return sign + strconv.FormatInt(n/1000, 10) + "." + frac
	case String:
		return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(b.Str) + `"`
	case Token:
		return b.Str
	case ByteSeq:
		return ":" + base64.StdEncoding.EncodeToString(b.Bytes) + ":"
	case Boolean:
		if b.Bool {
			return "?1"
		}
		return "?0"
	}
	return ""
}

func (ps Params) String() string {
	var b strings.Builder
	for _, p := range ps {
		b.WriteString(";" + p.Key)
		if !(p.Value.Kind == Boolean && p.Value.Bool) {
			b.WriteString("=" + p.Value.String())
		}
	}
	return b.String()
}

func (it Item) String() string { return it.Bare.String() + it.Params.String() }

func (m Member) String() string {
	if !m.Inner {
		return m.Bare.String() + m.Params.String()
	}
	parts := make([]string, len(m.Items))
	for i, it := range m.Items {
		parts[i] = it.String()
	}
	return "(" + strings.Join(parts, " ") + ")" + m.Params.String()
}

// SerializeList is the strict serialization of a List.
func SerializeList(ms []Member) string {
	parts := make([]string, len(ms))
	for i, m := range ms {
		parts[i] = m.String()
	}
	return strings.Join(parts, ", ")
}

func (d Dictionary) String() string {
	parts := make([]string, len(d))
	for i, e := range d {
		if !e.Member.Inner && e.Member.Bare.Kind == Boolean && e.Member.Bare.Bool {
			parts[i] = e.Key + e.Member.Params.String()
		} else {
			parts[i] = e.Key + "=" + e.Member.String()
		}
	}
	return strings.Join(parts, ", ")
}
