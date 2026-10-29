package main

// http-message-signatures.json: vectors for the 0.2.0 features. Every
// expected component value and signature base below is written out by hand
// from RFC 9421 (and RFC 8941 for structured fields), not computed by an
// implementation; the generator only signs the expected bases. The RFC's own
// Ed25519 example (B.2.6) must reproduce its published signature.

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/messhio/messh/spec/vectors/gen/internal/webbotauth"
)

type hdr [2]string

type message struct {
	Method        string   `json:"method,omitempty"`
	URL           string   `json:"url,omitempty"`
	RequestTarget string   `json:"request_target,omitempty"`
	Status        int      `json:"status,omitempty"`
	Headers       []hdr    `json:"headers"`
	Trailers      []hdr    `json:"trailers,omitempty"`
	Body          *string  `json:"body,omitempty"`
	Request       *message `json:"request,omitempty"`
}

// with returns a copy of m with headers added, or replaced when replace is set.
func (m message) with(replace bool, hs ...hdr) message {
	c := m
	c.Headers = nil
	for _, h := range m.Headers {
		drop := false
		for _, n := range hs {
			drop = drop || (replace && strings.EqualFold(h[0], n[0]))
		}
		if !drop {
			c.Headers = append(c.Headers, h)
		}
	}
	c.Headers = append(c.Headers, hs...)
	return c
}

type vkey struct {
	SeedHex    string `json:"seed_hex"`
	X          string `json:"x"`
	Thumbprint string `json:"thumbprint"`
	priv       ed25519.PrivateKey
}

func newKey(seed []byte) vkey {
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	return vkey{hex.EncodeToString(seed), base64.RawURLEncoding.EncodeToString(pub), webbotauth.Thumbprint(pub), priv}
}

func (k vkey) sign(base string) string {
	return base64.StdEncoding.EncodeToString(ed25519.Sign(k.priv, []byte(base)))
}

// jwk is the key as a compact JWK, members in a fixed order (directory bodies are compared byte for byte).
func (k vkey) jwk() string {
	return `{"kty":"OKP","crv":"Ed25519","x":"` + k.X + `","kid":"` + k.Thumbprint + `"}`
}

type sfCase struct {
	Name      string `json:"name"`
	Type      string `json:"type"`
	Input     string `json:"input"`
	Canonical string `json:"canonical"`
	Error     bool   `json:"error,omitempty"`
}

type componentCase struct {
	Name       string `json:"name"`
	Message    string `json:"message"`
	Component  string `json:"component"`
	Identifier string `json:"identifier,omitempty"`
	Value      string `json:"value"`
	Error      bool   `json:"error,omitempty"`
}

type signParams struct {
	Created int64  `json:"created,omitempty"`
	Expires int64  `json:"expires,omitempty"`
	KeyID   string `json:"keyid,omitempty"`
	Alg     string `json:"alg,omitempty"`
	Nonce   string `json:"nonce,omitempty"`
	Tag     string `json:"tag,omitempty"`
}

type clientCase struct {
	Identity        string `json:"identity"`
	Registry        string `json:"registry"`
	AgentDictionary bool   `json:"agent_dictionary"`
	Created         int64  `json:"created"`
	Nonce           string `json:"nonce"`
}

type hsSignCase struct {
	Name       string            `json:"name"`
	Message    message           `json:"message"`
	Key        string            `json:"key"`
	Label      string            `json:"label"`
	Components []string          `json:"components"`
	Params     signParams        `json:"params"`
	Base       string            `json:"expected_base"`
	Headers    map[string]string `json:"expected_headers"`
	Client     *clientCase       `json:"client,omitempty"`
}

type hsVerifyCase struct {
	Name   string            `json:"name"`
	Msg    message           `json:"message"`
	Keys   map[string]string `json:"keys"` // keyid → key name
	Label  string            `json:"label,omitempty"`
	Tag    string            `json:"tag,omitempty"`
	Now    int64             `json:"now"`
	MaxAge int64             `json:"max_age,omitempty"`
	Expect string            `json:"expect"`
	Picked string            `json:"expect_label,omitempty"`
}

type wbaCase struct {
	Name        string              `json:"name"`
	Msg         message             `json:"message"`
	Now         int64               `json:"now"`
	Trust       []string            `json:"trust"`
	Require     []string            `json:"require,omitempty"`
	Directories map[string][]string `json:"directories"` // agent URL → key names
	Expect      string              `json:"expect"`
	Identity    string              `json:"identity,omitempty"`
	External    bool                `json:"external,omitempty"`
}

type dirVerifyCase struct {
	Name    string            `json:"name"`
	URL     string            `json:"url"`
	Headers map[string]string `json:"headers"`
	Body    string            `json:"body"`
	Now     int64             `json:"now"`
	Signed  []string          `json:"expect_signed"`
}

func str(s string) *string { return &s }

func lines(ls ...string) string { return strings.Join(ls, "\n") }

func writeHTTPSig(out string, messhSeed []byte) {
	rfcSeed, _ := base64.RawURLEncoding.DecodeString("n4Ni-HpISpVObnQMW0wOhCKROaIKqKtW_2ZYb2p9KcU") // RFC 9421 B.1.4
	rfc := newKey(rfcSeed)
	if rfc.X != "JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs" {
		panic("RFC 9421 test-key-ed25519 doesn't match")
	}
	second := sha256.Sum256([]byte("messh web-bot-auth test vector key 2"))
	keys := map[string]vkey{"test-key-ed25519": rfc, "messh": newKey(messhSeed), "second": newKey(second[:])}
	mk, sk := keys["messh"], keys["second"]

	// --- messages ---
	testRequest := message{Method: "POST", URL: "https://example.com/foo?param=Value&Pet=dog", Headers: []hdr{
		{"Host", "example.com"},
		{"Date", "Tue, 20 Apr 2021 02:07:55 GMT"},
		{"Content-Type", "application/json"},
		{"Content-Digest", "sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:"},
		{"Content-Length", "18"},
	}, Body: str(`{"hello": "world"}`)}
	testResponse := message{Status: 200, Headers: []hdr{
		{"Date", "Tue, 20 Apr 2021 02:07:56 GMT"},
		{"Content-Type", "application/json"},
		{"Content-Digest", "sha-512=:mEWXIS7MaLRuGgxOBdODa3xqM1XdEvxoYhvlCFJ41QJgJc4GTsPp29l5oGX69wWdXymyU0rjJuahq4l5aGgfLQ==:"},
		{"Content-Length", "23"},
	}, Body: str(`{"message": "good dog"}`), Request: &testRequest}
	for _, m := range []message{testRequest, testResponse} {
		sum := sha512.Sum512([]byte(*m.Body))
		for _, h := range m.Headers {
			if h[0] == "Content-Digest" && h[1] != "sha-512=:"+base64.StdEncoding.EncodeToString(sum[:])+":" {
				panic("RFC 9421 Content-Digest doesn't match its body")
			}
		}
	}
	messages := map[string]message{
		"fields": {Method: "POST", URL: "https://www.example.com/path?param=value", Headers: []hdr{
			{"Host", "www.example.com"},
			{"Date", "Tue, 20 Apr 2021 02:07:56 GMT"},
			{"X-OWS-Header", "   Leading and trailing whitespace.   "},
			{"X-Obs-Fold-Header", "Obsolete\r\n    line folding."},
			{"Cache-Control", "max-age=60"},
			{"Cache-Control", "   must-revalidate"},
			{"Example-Dict", " a=1,    b=2;x=1;y=2,   c=(a   b   c)"},
			{"X-Empty-Header", ""},
			{"Example-Header", "value, with, lots"},
			{"Example-Header", "of, commas"},
		}},
		"dict-members":   {Method: "GET", URL: "https://www.example.com/", Headers: []hdr{{"Example-Dict", "  a=1, b=2;x=1;y=2, c=(a   b    c), d"}}},
		"single-line-bs": {Method: "GET", URL: "https://www.example.com/", Headers: []hdr{{"Example-Header", "value, with, lots, of, commas"}}},
		"query-params":   {Method: "GET", URL: "https://www.example.com/path?param=value&foo=bar&baz=batman&qux=", Headers: []hdr{{"Host", "www.example.com"}}},
		"query-encoding": {Method: "GET", URL: "https://www.example.com/parameters?var=this%20is%20a%20big%0Amultiline%20value&bar=with+plus+whitespace&fa%C3%A7ade%22%3A%20=something", Headers: []hdr{}},
		"query-dupe":     {Method: "GET", URL: "https://www.example.com/path?a=1&a=2&b=", Headers: []hdr{}},
		"no-host":        {Method: "GET", URL: "https://WWW.Example.com:8443/", Headers: []hdr{}},
		"empty-path":     {Method: "GET", URL: "http://example.com", Headers: []hdr{}},
		"encoded-path":   {Method: "GET", URL: "https://example.com/a%20b/c?x=%2D", Headers: []hdr{}},
		"options-star":   {Method: "OPTIONS", URL: "https://www.example.com/", RequestTarget: "*", Headers: []hdr{{"Host", "www.example.com"}}},
		"test-request":   testRequest,
		"test-response":  testResponse,
		"trailers":       {Status: 200, Headers: []hdr{{"Content-Type", "text/plain"}, {"Trailer", "Expires"}}, Trailers: []hdr{{"Expires", "Wed, 9 Nov 2022 07:28:00 GMT"}}},
	}

	// --- structured fields (RFC 8941) ---
	sfs := []sfCase{
		{"dict-ows", "dictionary", "a=1,    b=2;x=1;y=2,   c=(a   b   c)", "a=1, b=2;x=1;y=2, c=(a b c)", false},
		{"dict-boolean-member", "dictionary", "a=1, b=2;x=1;y=2, c=(a   b    c), d", "a=1, b=2;x=1;y=2, c=(a b c), d", false},
		{"dict-explicit-booleans", "dictionary", "a=?1, b=?0", "a, b=?0", false},
		{"dict-boolean-params", "dictionary", "a;x=?1;y=?0", "a;x;y=?0", false},
		{"dict-duplicate-key-last-wins", "dictionary", "a=1, b=2, a=3", "a=3, b=2", false},
		{"dict-signature-input", "dictionary", `sig1=("@method" "@path";req);created=1;keyid="k"`, `sig1=("@method" "@path";req);created=1;keyid="k"`, false},
		{"dict-empty", "dictionary", "", "", false},
		{"list-mixed", "list", `1, "two", three, :Zm91cg==:, ?1, 5.5`, `1, "two", three, :Zm91cg==:, ?1, 5.5`, false},
		{"list-inner", "list", `(a b);q=1, ("c" 2)`, `(a b);q=1, ("c" 2)`, false},
		{"list-empty-inner", "list", "()", "()", false},
		{"list-ows", "list", "a ,  b", "a, b", false},
		{"item-string-escapes", "item", `"a\"b\\c"`, `"a\"b\\c"`, false},
		{"item-token", "item", "*foo/bar:baz", "*foo/bar:baz", false},
		{"item-decimal-trailing-zero", "item", "1.50", "1.5", false},
		{"item-decimal-negative", "item", "-0.250", "-0.25", false},
		{"item-decimal-whole", "item", "3.0", "3.0", false},
		{"item-decimal-three-places", "item", "1.123", "1.123", false},
		{"item-integer", "item", "-12345", "-12345", false},
		{"item-bytes", "item", ":YWJj:", ":YWJj:", false},
		{"item-params", "item", `"s";a=1;b="x";c`, `"s";a=1;b="x";c`, false},
		{"item-surrounding-spaces", "item", "  token  ", "token", false},
		{"err-dict-trailing-comma", "dictionary", "a=1,", "", true},
		{"err-dict-uppercase-key", "dictionary", "A=1", "", true},
		{"err-dict-missing-comma", "dictionary", "a=1 b=2", "", true},
		{"err-dict-unterminated-inner", "dictionary", "a=(1 2", "", true},
		{"err-item-unterminated-string", "item", `"abc`, "", true},
		{"err-item-four-decimals", "item", "1.1234", "", true},
		{"err-item-long-integer", "item", "1234567890123456", "", true},
		{"err-item-bad-boolean", "item", "?2", "", true},
		{"err-item-non-ascii", "item", `"é"`, "", true},
	}

	// --- component values (RFC 9421 §2.1, §2.2, §2.4) ---
	cc := func(name, msg, component, identifier, value string) componentCase {
		return componentCase{name, msg, component, identifier, value, false}
	}
	ce := func(name, msg, component string) componentCase {
		return componentCase{Name: name, Message: msg, Component: component, Error: true}
	}
	components := []componentCase{
		cc("field-host", "fields", "host", `"host"`, "www.example.com"),
		cc("field-date", "fields", "date", `"date"`, "Tue, 20 Apr 2021 02:07:56 GMT"),
		cc("field-name-lowercased", "fields", "Date", `"date"`, "Tue, 20 Apr 2021 02:07:56 GMT"),
		cc("field-ows-trimmed", "fields", "x-ows-header", `"x-ows-header"`, "Leading and trailing whitespace."),
		cc("field-obs-fold", "fields", "x-obs-fold-header", `"x-obs-fold-header"`, "Obsolete line folding."),
		cc("field-multiple-lines", "fields", "cache-control", `"cache-control"`, "max-age=60, must-revalidate"),
		cc("field-raw-dictionary", "fields", "example-dict", `"example-dict"`, "a=1,    b=2;x=1;y=2,   c=(a   b   c)"),
		cc("field-empty", "fields", "x-empty-header", `"x-empty-header"`, ""),
		cc("field-sf", "fields", `"example-dict";sf`, `"example-dict";sf`, "a=1, b=2;x=1;y=2, c=(a b c)"),
		cc("field-key-integer", "dict-members", `"example-dict";key="a"`, `"example-dict";key="a"`, "1"),
		cc("field-key-boolean", "dict-members", `"example-dict";key="d"`, `"example-dict";key="d"`, "?1"),
		cc("field-key-params", "dict-members", `"example-dict";key="b"`, `"example-dict";key="b"`, "2;x=1;y=2"),
		cc("field-key-inner-list", "dict-members", `"example-dict";key="c"`, `"example-dict";key="c"`, "(a b c)"),
		ce("field-key-missing", "dict-members", `"example-dict";key="zz"`),
		cc("field-commas", "fields", "example-header", `"example-header"`, "value, with, lots, of, commas"),
		cc("field-bs-two-lines", "fields", `"example-header";bs`, `"example-header";bs`, ":dmFsdWUsIHdpdGgsIGxvdHM=:, :b2YsIGNvbW1hcw==:"),
		cc("field-bs-one-line", "single-line-bs", `"example-header";bs`, `"example-header";bs`, ":dmFsdWUsIHdpdGgsIGxvdHMsIG9mLCBjb21tYXM=:"),
		ce("field-bs-with-sf", "fields", `"example-header";bs;sf`),
		ce("field-unknown-parameter", "fields", `"date";foo`),
		ce("field-sf-unknown-type", "fields", `"cache-control";sf`),
		ce("field-missing", "fields", "x-missing"),
		cc("method", "fields", "@method", `"@method"`, "POST"),
		cc("target-uri", "fields", "@target-uri", `"@target-uri"`, "https://www.example.com/path?param=value"),
		cc("authority", "fields", "@authority", `"@authority"`, "www.example.com"),
		cc("scheme", "fields", "@scheme", `"@scheme"`, "https"),
		cc("request-target", "fields", "@request-target", `"@request-target"`, "/path?param=value"),
		cc("path", "fields", "@path", `"@path"`, "/path"),
		cc("query", "fields", "@query", `"@query"`, "?param=value"),
		cc("authority-from-url", "no-host", "@authority", `"@authority"`, "www.example.com:8443"),
		cc("target-uri-from-url", "no-host", "@target-uri", `"@target-uri"`, "https://www.example.com:8443/"),
		cc("path-empty", "empty-path", "@path", `"@path"`, "/"),
		cc("query-absent", "empty-path", "@query", `"@query"`, "?"),
		cc("target-uri-empty-path", "empty-path", "@target-uri", `"@target-uri"`, "http://example.com/"),
		cc("scheme-http", "empty-path", "@scheme", `"@scheme"`, "http"),
		cc("request-target-empty-path", "empty-path", "@request-target", `"@request-target"`, "/"),
		cc("path-percent-encoded", "encoded-path", "@path", `"@path"`, "/a%20b/c"),
		cc("query-percent-encoded", "encoded-path", "@query", `"@query"`, "?x=%2D"),
		cc("request-target-asterisk", "options-star", "@request-target", `"@request-target"`, "*"),
		cc("query-param", "query-params", `"@query-param";name="baz"`, `"@query-param";name="baz"`, "batman"),
		cc("query-param-empty", "query-params", `"@query-param";name="qux"`, `"@query-param";name="qux"`, ""),
		cc("query-param-first", "query-params", `"@query-param";name="param"`, `"@query-param";name="param"`, "value"),
		cc("query-param-encoded-value", "query-encoding", `"@query-param";name="var"`, `"@query-param";name="var"`, "this%20is%20a%20big%0Amultiline%20value"),
		cc("query-param-plus", "query-encoding", `"@query-param";name="bar"`, `"@query-param";name="bar"`, "with%20plus%20whitespace"),
		cc("query-param-encoded-name", "query-encoding", `"@query-param";name="fa%C3%A7ade%22%3A%20"`, `"@query-param";name="fa%C3%A7ade%22%3A%20"`, "something"),
		ce("query-param-missing", "query-params", `"@query-param";name="missing"`),
		ce("query-param-repeated", "query-dupe", `"@query-param";name="a"`),
		cc("query-param-once", "query-dupe", `"@query-param";name="b"`, `"@query-param";name="b"`, ""),
		ce("query-param-no-name", "query-params", "@query-param"),
		ce("status-on-request", "fields", "@status"),
		cc("status", "test-response", "@status", `"@status"`, "200"),
		cc("req-authority", "test-response", `"@authority";req`, `"@authority";req`, "example.com"),
		cc("req-method", "test-response", `"@method";req`, `"@method";req`, "POST"),
		cc("req-path", "test-response", `"@path";req`, `"@path";req`, "/foo"),
		cc("req-query", "test-response", `"@query";req`, `"@query";req`, "?param=Value&Pet=dog"),
		cc("req-field", "test-response", `"content-type";req`, `"content-type";req`, "application/json"),
		ce("req-on-request", "fields", `"@method";req`),
		ce("req-status", "test-response", `"@status";req`),
		cc("trailer", "trailers", `"expires";tr`, `"expires";tr`, "Wed, 9 Nov 2022 07:28:00 GMT"),
		ce("trailer-not-a-header", "trailers", "expires"),
		ce("unknown-derived", "fields", "@foo"),
	}

	// --- signing ---
	member := func(label, inner string) string { return label + "=" + inner }
	sigParams := func(comps string, p signParams) string {
		s := "(" + comps + ")"
		if p.Created != 0 {
			s += fmt.Sprintf(";created=%d", p.Created)
		}
		if p.Expires != 0 {
			s += fmt.Sprintf(";expires=%d", p.Expires)
		}
		for _, kv := range [][2]string{{"keyid", p.KeyID}, {"alg", p.Alg}, {"nonce", p.Nonce}, {"tag", p.Tag}} {
			if kv[1] != "" {
				s += ";" + kv[0] + `="` + kv[1] + `"`
			}
		}
		return s
	}
	var signs []hsSignCase
	sign := func(name string, m message, key, label string, comps []string, inner string, p signParams, baseLines ...string) hsSignCase {
		params := sigParams(inner, p)
		base := lines(append(baseLines, `"@signature-params": `+params)...)
		c := hsSignCase{name, m, key, label, comps, p, base, map[string]string{
			"Signature-Input": member(label, params),
			"Signature":       member(label, ":"+keys[key].sign(base)+":"),
		}, nil}
		signs = append(signs, c)
		return c
	}
	b26 := sign("rfc9421-b26-ed25519", testRequest, "test-key-ed25519", "sig-b26",
		[]string{"date", "@method", "@path", "@authority", "content-type", "content-length"},
		`"date" "@method" "@path" "@authority" "content-type" "content-length"`,
		signParams{Created: 1618884473, KeyID: "test-key-ed25519"},
		`"date": Tue, 20 Apr 2021 02:07:55 GMT`, `"@method": POST`, `"@path": /foo`, `"@authority": example.com`,
		`"content-type": application/json`, `"content-length": 18`)
	if b26.Headers["Signature"] != "sig-b26=:wqcAqbmYJ2ji2glfAMaRy4gruYYnx2nEFN2HN6jrnDnQCK1u02Gb04v9EDgwUPiu4A0w6vuQv5lIp5WPpBKRCw==:" {
		panic("RFC 9421 B.2.6 signature doesn't match: " + b26.Headers["Signature"])
	}
	resp := sign("response-with-request-components", testResponse, "test-key-ed25519", "reqres",
		[]string{"@status", "content-type", "content-digest", `"@authority";req`, `"@method";req`, `"@path";req`, `"@query";req`, `"content-digest";req`},
		`"@status" "content-type" "content-digest" "@authority";req "@method";req "@path";req "@query";req "content-digest";req`,
		signParams{Created: 1618884479, KeyID: "test-key-ed25519", Alg: "ed25519"},
		`"@status": 200`, `"content-type": application/json`,
		`"content-digest": sha-512=:mEWXIS7MaLRuGgxOBdODa3xqM1XdEvxoYhvlCFJ41QJgJc4GTsPp29l5oGX69wWdXymyU0rjJuahq4l5aGgfLQ==:`,
		`"@authority";req: example.com`, `"@method";req: POST`, `"@path";req: /foo`, `"@query";req: ?param=Value&Pet=dog`,
		`"content-digest";req: sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:`)
	queryFields := messages["query-params"].with(false,
		hdr{"Example-Dict", " a=1,    b=2;x=1;y=2,   c=(a   b   c)"}, hdr{"Example-Header", "value, with, lots"}, hdr{"Example-Header", "of, commas"})
	fields := sign("parameters-and-derived-components", queryFields, "messh", "sig1",
		[]string{`"@query-param";name="baz"`, `"example-dict";key="b"`, `"example-dict";sf`, `"example-header";bs`, "@target-uri", "@scheme", "@request-target"},
		`"@query-param";name="baz" "example-dict";key="b" "example-dict";sf "example-header";bs "@target-uri" "@scheme" "@request-target"`,
		signParams{Created: 1760000000, Expires: 1760000060, KeyID: mk.Thumbprint, Alg: "ed25519", Nonce: "nonce-fields-1", Tag: "custom"},
		`"@query-param";name="baz": batman`, `"example-dict";key="b": 2;x=1;y=2`, `"example-dict";sf: a=1, b=2;x=1;y=2, c=(a b c)`,
		`"example-header";bs: :dmFsdWUsIHdpdGgsIGxvdHM=:, :b2YsIGNvbW1hcw==:`,
		`"@target-uri": https://www.example.com/path?param=value&foo=bar&baz=batman&qux=`, `"@scheme": https`,
		`"@request-target": /path?param=value&foo=bar&baz=batman&qux=`)
	digest := sign("request-content-digest", testRequest, "test-key-ed25519", "sig1",
		[]string{"@method", "@authority", "@path", "content-digest"}, `"@method" "@authority" "@path" "content-digest"`,
		signParams{Created: 1618884480, KeyID: "test-key-ed25519"},
		`"@method": POST`, `"@authority": example.com`, `"@path": /foo`,
		`"content-digest": sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:`)
	hello := message{Method: "GET", URL: "https://app.example/api/hello", Headers: []hdr{}}
	wbaParams := func(nonce string, k vkey) signParams {
		return signParams{Created: 1760000000, Expires: 1760000060, KeyID: k.Thumbprint, Alg: "ed25519", Nonce: nonce, Tag: "web-bot-auth"}
	}
	dictAgent := hello.with(false, hdr{"Signature-Agent", `sig1="https://registry.example/mukul"`})
	dict := sign("web-bot-auth-dictionary-agent", dictAgent, "messh", "sig1",
		[]string{"@method", "@authority", "@path", `"signature-agent";key="sig1"`},
		`"@method" "@authority" "@path" "signature-agent";key="sig1"`, wbaParams("nonce-dict-1", mk),
		`"@method": GET`, `"@authority": app.example`, `"@path": /api/hello`, `"signature-agent";key="sig1": "https://registry.example/mukul"`)
	signs[len(signs)-1].Client = &clientCase{"mukul", "https://registry.example", true, 1760000000, "nonce-dict-1"}
	signs[len(signs)-1].Headers["Signature-Agent"] = `sig1="https://registry.example/mukul"`

	// --- generic verification ---
	signed := func(m message, cs ...hsSignCase) message {
		var in, sig []string
		for _, c := range cs {
			in, sig = append(in, c.Headers["Signature-Input"]), append(sig, c.Headers["Signature"])
		}
		return m.with(true, hdr{"Signature-Input", strings.Join(in, ", ")}, hdr{"Signature", strings.Join(sig, ", ")})
	}
	rfcKeys := map[string]string{"test-key-ed25519": "test-key-ed25519"}
	both := map[string]string{"test-key-ed25519": "test-key-ed25519", mk.Thumbprint: "messh"}
	second2 := sign("second-signature", queryFields, "test-key-ed25519", "sig2", []string{"@method", "@authority"},
		`"@method" "@authority"`, signParams{Created: 1760000000, KeyID: "test-key-ed25519", Tag: "other"},
		`"@method": GET`, `"@authority": www.example.com`)
	signs = signs[:len(signs)-1] // only used to build the two-signature message
	twoSigs := signed(queryFields, fields, second2)
	tamperedDate := signed(testRequest, b26).with(true, hdr{"Date", "Tue, 20 Apr 2021 02:07:56 GMT"})
	tamperedReq := signed(testResponse, resp)
	otherReq := testRequest
	otherReq.URL = "https://example.com/bar?param=Value&Pet=dog"
	tamperedReq.Request = &otherReq
	digestBad := signed(testRequest, digest)
	digestBad.Body = str(`{"hello": "there"}`)
	dupLabel := testRequest
	dupLabel.Headers = append(append([]hdr{}, testRequest.Headers...),
		hdr{"Signature-Input", b26.Headers["Signature-Input"]}, hdr{"Signature-Input", b26.Headers["Signature-Input"]},
		hdr{"Signature", b26.Headers["Signature"]}, hdr{"Signature", b26.Headers["Signature"]})
	dupComponent := testRequest.with(true, hdr{"Signature-Input", `sig1=("@method" "@method");created=1618884473;keyid="test-key-ed25519"`},
		hdr{"Signature", "sig1=:AAAA:"})
	algMismatch := signed(testRequest, b26).with(true, hdr{"Signature-Input", b26.Headers["Signature-Input"] + `;alg="rsa-pss-sha512"`})
	verifies := []hsVerifyCase{
		{"rfc9421-b26-ok", signed(testRequest, b26), rfcKeys, "", "", 1618884480, 0, "ok", "sig-b26"},
		{"rfc9421-b26-tampered", tamperedDate, rfcKeys, "", "", 1618884480, 0, "bad_signature", ""},
		{"rfc9421-b26-unknown-key", signed(testRequest, b26), map[string]string{}, "", "", 1618884480, 0, "unknown_key", ""},
		{"rfc9421-b26-too-old", signed(testRequest, b26), rfcKeys, "", "", 1618884473 + 3600, 60, "clock_skew", ""},
		{"rfc9421-b26-from-the-future", signed(testRequest, b26), rfcKeys, "", "", 1618884473 - 3600, 0, "clock_skew", ""},
		{"response-ok", signed(testResponse, resp), rfcKeys, "", "", 1618884480, 0, "ok", "reqres"},
		{"response-other-request", tamperedReq, rfcKeys, "", "", 1618884480, 0, "bad_signature", ""},
		{"content-digest-ok", signed(testRequest, digest), rfcKeys, "", "", 1618884481, 0, "ok", "sig1"},
		{"content-digest-mismatch", digestBad, rfcKeys, "", "", 1618884481, 0, "digest_mismatch", ""},
		{"pick-by-tag", twoSigs, both, "", "custom", 1760000005, 0, "ok", "sig1"},
		{"pick-by-label", twoSigs, both, "sig2", "", 1760000005, 0, "ok", "sig2"},
		{"pick-missing-tag", twoSigs, both, "", "absent", 1760000005, 0, "bad_signature", ""},
		{"pick-ambiguous", twoSigs, both, "", "", 1760000005, 0, "bad_signature", ""},
		{"expired", signed(queryFields, fields), both, "", "custom", 1760000061, 0, "clock_skew", ""},
		{"duplicate-label", dupLabel, rfcKeys, "", "", 1618884480, 0, "bad_signature", ""},
		{"duplicate-component", dupComponent, rfcKeys, "", "", 1618884480, 0, "bad_signature", ""},
		{"alg-not-ed25519", algMismatch, rfcKeys, "", "", 1618884480, 0, "bad_signature", ""},
		{"missing-signature", testRequest, rfcKeys, "", "", 1618884480, 0, "missing_signature", ""},
	}

	// --- Web Bot Auth verifier ---
	wbaSign := func(m message, k vkey, nonce, inner string, baseLines ...string) message {
		p := wbaParams(nonce, k)
		params := sigParams(inner, p)
		base := lines(append(baseLines, `"@signature-params": `+params)...)
		return m.with(true, hdr{"Signature-Input", member("sig1", params)}, hdr{"Signature", member("sig1", ":"+k.sign(base)+":")})
	}
	defaultInner := `"@method" "@authority" "@path" "signature-agent"`
	helloBase := []string{`"@method": GET`, `"@authority": app.example`, `"@path": /api/hello`}
	agentMsg := func(agent string, k vkey, nonce string) message {
		m := hello.with(false, hdr{"Signature-Agent", agent})
		return wbaSign(m, k, nonce, defaultInner, append(helloBase, `"signature-agent": `+agent)...)
	}
	mukulDir := map[string][]string{"https://registry.example/mukul": {"messh"}}
	externalDir := map[string][]string{"https://agent.example": {"second"}}
	inline := "data:application/http-message-signatures-directory;base64," + base64.StdEncoding.EncodeToString([]byte(`{"keys":[`+sk.jwk()+`]}`))
	twoAgents := `a="https://registry.example/bob", b="https://registry.example/mukul"`
	byKey := func(key string) message {
		m := hello.with(false, hdr{"Signature-Agent", twoAgents})
		sa := `"signature-agent";key="` + key + `"`
		value := map[string]string{"a": `"https://registry.example/bob"`, "b": `"https://registry.example/mukul"`}[key]
		return wbaSign(m, mk, "nonce-key-"+key, `"@method" "@authority" "@path" `+sa, append(helloBase, sa+": "+value)...)
	}
	minimal := func() message {
		m := hello.with(false, hdr{"Signature-Agent", `"https://agent.example"`})
		return wbaSign(m, sk, "nonce-minimal", `"@authority" "signature-agent"`, `"@authority": app.example`, `"signature-agent": "https://agent.example"`)
	}
	items := message{Method: "GET", URL: "https://app.example/api/items?limit=10", Headers: []hdr{{"Signature-Agent", `"https://registry.example/mukul"`}}}
	targetURI := wbaSign(items, mk, "nonce-target-uri", `"@method" "@target-uri" "signature-agent"`,
		`"@method": GET`, `"@target-uri": https://app.example/api/items?limit=10`, `"signature-agent": "https://registry.example/mukul"`)
	minimalQuery := wbaSign(items.with(true, hdr{"Signature-Agent", `"https://agent.example"`}), sk, "nonce-minimal-query",
		`"@authority" "signature-agent"`, `"@authority": app.example`, `"signature-agent": "https://agent.example"`)
	dictByLabel := wbaSign(dictAgent, mk, "nonce-dict-label", defaultInner,
		append(helloBase, `"signature-agent": sig1="https://registry.example/mukul"`)...)
	stringAgent := agentMsg(`"https://registry.example/mukul"`, mk, "nonce-string")
	dupWBA := stringAgent
	dupWBA.Headers = nil
	for _, h := range stringAgent.Headers {
		dupWBA.Headers = append(dupWBA.Headers, h)
		if h[0] == "Signature-Input" || h[0] == "Signature" {
			dupWBA.Headers = append(dupWBA.Headers, h)
		}
	}
	twoDirs := map[string][]string{"https://registry.example/mukul": {"messh"}, "https://registry.example/bob": {"second"}}
	const now = 1760000005
	wbas := []wbaCase{
		{"string-agent", stringAgent, now, []string{"*"}, nil, mukulDir, "ok", "mukul", false},
		{"dictionary-agent-by-key", signed(dictAgent, dict), now, []string{"*"}, nil, mukulDir, "ok", "mukul", false},
		{"dictionary-agent-by-label", dictByLabel, now, []string{"*"}, nil, mukulDir, "ok", "mukul", false},
		{"dictionary-member-chosen-by-key", byKey("b"), now, []string{"*"}, nil, twoDirs, "ok", "mukul", false},
		{"dictionary-member-with-other-keys", byKey("a"), now, []string{"*"}, nil, twoDirs, "unknown_key", "", false},
		{"external-agent", agentMsg(`"https://agent.example"`, sk, "nonce-external"), now, []string{"https://agent.example"}, nil, externalDir, "ok", "https://agent.example", true},
		{"external-agent-not-trusted", agentMsg(`"https://agent.example"`, sk, "nonce-external"), now, []string{"*"}, nil, externalDir, "untrusted", "", false},
		{"external-agent-with-path", agentMsg(`"https://agent.example/bot"`, sk, "nonce-external-path"), now, []string{"https://agent.example"}, nil, externalDir, "untrusted", "", false},
		{"inline-keys", agentMsg(`"`+inline+`"`, sk, "nonce-inline"), now, []string{"jwk:" + sk.Thumbprint}, nil, map[string][]string{}, "ok", "jwk:" + sk.Thumbprint, true},
		{"inline-keys-not-trusted", agentMsg(`"`+inline+`"`, sk, "nonce-inline"), now, []string{"*"}, nil, map[string][]string{}, "untrusted", "", false},
		{"minimal-components-default", minimal(), now, []string{"https://agent.example"}, nil, externalDir, "bad_signature", "", false},
		{"minimal-components-allowed", minimal(), now, []string{"https://agent.example"}, []string{"@authority", "signature-agent"}, externalDir, "ok", "https://agent.example", true},
		{"minimal-components-query-uncovered", minimalQuery, now, []string{"https://agent.example"}, []string{"@authority", "signature-agent"}, externalDir, "bad_signature", "", false},
		{"target-uri-covers-authority-path-query", targetURI, now, []string{"*"}, nil, mukulDir, "ok", "mukul", false},
		{"duplicate-label", dupWBA, now, []string{"*"}, nil, mukulDir, "bad_signature", "", false},
	}

	// --- signed key directories (draft-meunier-http-message-signatures-directory §5) ---
	body := `{"keys":[` + mk.jwk() + `,` + sk.jwk() + `]}`
	sum := sha256.Sum256([]byte(body))
	contentDigest := "sha-256=:" + base64.StdEncoding.EncodeToString(sum[:]) + ":"
	var dirIn, dirSig []string
	for i, k := range []vkey{mk, sk} {
		p := signParams{Created: 1760000000, Expires: 1760000300, KeyID: k.Thumbprint, Alg: "ed25519", Tag: "http-message-signatures-directory"}
		params := sigParams(`"@authority";req "content-digest"`, p)
		base := lines(`"@authority";req: agent.example`, `"content-digest": `+contentDigest, `"@signature-params": `+params)
		label := fmt.Sprintf("binding%d", i)
		dirIn, dirSig = append(dirIn, member(label, params)), append(dirSig, member(label, ":"+k.sign(base)+":"))
	}
	dirHeaders := map[string]string{"Content-Digest": contentDigest, "Signature-Input": strings.Join(dirIn, ", "), "Signature": strings.Join(dirSig, ", ")}
	// The form Cloudflare's example directory served in 2025: plain "@authority", its own parameter order.
	plainParams := `("@authority");created=1760000000;keyid="` + mk.Thumbprint + `";alg="ed25519";expires=1760000300;tag="http-message-signatures-directory"`
	plainHeaders := map[string]string{
		"Signature-Input": member("binding0", plainParams),
		"Signature":       member("binding0", ":"+mk.sign(lines(`"@authority": agent.example`, `"@signature-params": `+plainParams))+":"),
	}
	dirURL := "https://agent.example/.well-known/http-message-signatures-directory"
	dirVerifies := []dirVerifyCase{
		{"signed", dirURL, dirHeaders, body, 1760000010, []string{mk.Thumbprint, sk.Thumbprint}},
		{"other-authority", "https://evil.example/.well-known/http-message-signatures-directory", dirHeaders, body, 1760000010, []string{}},
		{"body-changed", dirURL, dirHeaders, strings.Replace(body, mk.X, sk.X, 1), 1760000010, []string{}},
		{"expired", dirURL, dirHeaders, body, 1760000301, []string{}},
		{"unsigned", dirURL, map[string]string{}, body, 1760000010, []string{}},
		{"plain-authority", dirURL, plainHeaders, body, 1760000010, []string{mk.Thumbprint}},
	}

	doc := map[string]any{
		"description":       "messh 0.2.0 conformance vectors: RFC 9421 HTTP message signatures for any message, RFC 8941 structured fields, Web Bot Auth agents beyond messh identities, and signed key directories. Expected values are written by hand from the RFCs (spec/vectors/gen/httpsig.go); the generator only signs them.",
		"keys":              keys,
		"field_types":       map[string]string{"example-dict": "dictionary"},
		"messages":          messages,
		"structured_fields": sfs,
		"components":        components,
		"sign":              signs,
		"verify":            verifies,
		"web_bot_auth": map[string]any{
			"registry": "https://registry.example",
			"notes":    "Build a verifier with the trust list, the registry, required components when given, the clock at now, and a directory resolver that answers from directories (agent URL → key names). Inline keys need no resolver.",
			"cases":    wbas,
		},
		"directory": map[string]any{
			"sign": map[string]any{
				"authority": "agent.example", "keys": []string{"messh", "second"}, "created": 1760000000, "expires_in": 300,
				"expected_body": body, "expected_headers": dirHeaders,
			},
			"verify": dirVerifies,
		},
	}
	b, _ := json.MarshalIndent(doc, "", "  ")
	must(os.WriteFile(filepath.Join(out, "http-message-signatures.json"), append(b, '\n'), 0o644))
}
