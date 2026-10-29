// Package vectors loads spec/vectors/http-message-signatures.json for tests.
package vectors

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"runtime"

	"messh.io/go/messh/httpsig"
)

// Message is a vector message.
type Message struct {
	Method        string      `json:"method"`
	URL           string      `json:"url"`
	RequestTarget string      `json:"request_target"`
	Status        int         `json:"status"`
	Headers       [][2]string `json:"headers"`
	Trailers      [][2]string `json:"trailers"`
	Body          *string     `json:"body"`
	Request       *Message    `json:"request"`
}

func header(kvs [][2]string) http.Header {
	h := http.Header{}
	for _, kv := range kvs {
		h.Add(kv[0], kv[1])
	}
	return h
}

// Build turns the vector into an httpsig message.
func (v *Message) Build() *httpsig.Message {
	m := &httpsig.Message{Header: header(v.Headers)}
	if v.URL != "" {
		var err error
		if m, err = httpsig.NewRequest(v.Method, v.URL, m.Header, nil); err != nil {
			panic(err)
		}
	}
	m.Status, m.RequestTarget = v.Status, v.RequestTarget
	if v.Trailers != nil {
		m.Trailer = header(v.Trailers)
	}
	if v.Body != nil {
		m.Body = []byte(*v.Body)
	}
	if v.Request != nil {
		m.Request = v.Request.Build()
	}
	return m
}

// Key is a vector key.
type Key struct {
	SeedHex    string `json:"seed_hex"`
	X          string `json:"x"`
	Thumbprint string `json:"thumbprint"`
}

// Private is the key's Ed25519 private key.
func (k Key) Private() ed25519.PrivateKey {
	seed, err := hex.DecodeString(k.SeedHex)
	if err != nil {
		panic(err)
	}
	return ed25519.NewKeyFromSeed(seed)
}

// Signer signs with a private key.
type Signer struct{ K ed25519.PrivateKey }

func (s Signer) Public() ed25519.PublicKey     { return s.K.Public().(ed25519.PublicKey) }
func (s Signer) Sign(d []byte) ([]byte, error) { return ed25519.Sign(s.K, d), nil }

// Doc is the vectors file.
type Doc struct {
	Keys             map[string]Key     `json:"keys"`
	FieldTypes       map[string]string  `json:"field_types"`
	Messages         map[string]Message `json:"messages"`
	StructuredFields []struct {
		Name, Type, Input, Canonical string
		Error                        bool
	} `json:"structured_fields"`
	Components []struct {
		Name, Message, Component, Identifier, Value string
		Error                                       bool
	} `json:"components"`
	Sign []struct {
		Name       string   `json:"name"`
		Message    Message  `json:"message"`
		Key        string   `json:"key"`
		Label      string   `json:"label"`
		Components []string `json:"components"`
		Params     struct {
			Created, Expires int64
			KeyID            string `json:"keyid"`
			Alg, Nonce, Tag  string
		} `json:"params"`
		Base    string            `json:"expected_base"`
		Headers map[string]string `json:"expected_headers"`
		Client  *struct {
			Identity, Registry, Nonce string
			AgentDictionary           bool `json:"agent_dictionary"`
			Created                   int64
		} `json:"client"`
	} `json:"sign"`
	Verify []struct {
		Name    string            `json:"name"`
		Message Message           `json:"message"`
		Keys    map[string]string `json:"keys"`
		Label   string            `json:"label"`
		Tag     string            `json:"tag"`
		Now     int64             `json:"now"`
		MaxAge  int64             `json:"max_age"`
		Expect  string            `json:"expect"`
		Picked  string            `json:"expect_label"`
	} `json:"verify"`
	WebBotAuth struct {
		Registry string `json:"registry"`
		Cases    []struct {
			Name        string              `json:"name"`
			Message     Message             `json:"message"`
			Now         int64               `json:"now"`
			Trust       []string            `json:"trust"`
			Require     []string            `json:"require"`
			Directories map[string][]string `json:"directories"`
			Expect      string              `json:"expect"`
			Identity    string              `json:"identity"`
			External    bool                `json:"external"`
		} `json:"cases"`
	} `json:"web_bot_auth"`
	Directory struct {
		Sign struct {
			Authority string            `json:"authority"`
			Keys      []string          `json:"keys"`
			Created   int64             `json:"created"`
			ExpiresIn int64             `json:"expires_in"`
			Body      string            `json:"expected_body"`
			Headers   map[string]string `json:"expected_headers"`
		} `json:"sign"`
		Verify []struct {
			Name    string            `json:"name"`
			URL     string            `json:"url"`
			Headers map[string]string `json:"headers"`
			Body    string            `json:"body"`
			Now     int64             `json:"now"`
			Signed  []string          `json:"expect_signed"`
		} `json:"verify"`
	} `json:"directory"`
}

// Load reads the vectors from the messh repo; ok is false outside it.
func Load() (doc *Doc, ok bool) {
	_, file, _, _ := runtime.Caller(0)
	b, err := os.ReadFile(filepath.Join(filepath.Dir(file), "../../../../spec/vectors/http-message-signatures.json"))
	if os.IsNotExist(err) {
		return nil, false
	}
	if err != nil {
		panic(err)
	}
	doc = &Doc{}
	if err := json.Unmarshal(b, doc); err != nil {
		panic(err)
	}
	return doc, true
}
