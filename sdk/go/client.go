// Package messh signs HTTP requests as a messh identity with Web Bot Auth
// (RFC 9421 HTTP Message Signatures, Ed25519, tag="web-bot-auth").
//
//	client, err := messh.NewClient("mukul", messh.WithKey(messh.KeyFile("~/.ssh/id_ed25519")))
//	// or, from MESSH_IDENTITY and MESSH_KEY / MESSH_KEY_FILE: messh.NewClientFromEnv()
//	resp, err := client.Get("https://api.example.com/hello")
//
// Verifiers find the public key at <registry>/<identity>/.well-known/http-message-signatures-directory.
// Verify incoming requests with package messh.io/go/messh/verify.
package messh

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"messh.io/go/messh/internal/wba"
)

// Version of this SDK.
const Version = "0.1.0"

// DefaultRegistry is where identities resolve unless WithRegistry says otherwise.
const DefaultRegistry = "https://messh.io"

// Error is returned for client-side problems. Code is stable:
// invalid_identity, invalid_key, invalid_option, sign_failed; from WhoAmI:
// not_published, registry_unreachable.
type Error struct {
	Code    string
	Message string
}

func (e *Error) Error() string { return "messh: " + e.Code + ": " + e.Message }

var identityRe = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{1,28}[a-z0-9])$`)

// Client signs requests as one identity. It is safe for concurrent use.
type Client struct {
	identity  string
	registry  string
	key       KeySource
	signer    Signer
	expiresIn time.Duration
	http      *http.Client
	now       func() time.Time
	nonce     func() string
}

// Option configures a Client.
type Option func(*Client) error

// WithKey sets the signing key. Default: KeyFile("~/.ssh/id_ed25519"); for
// ssh-agent, SSHAgent("").
func WithKey(k KeySource) Option { return func(c *Client) error { c.key = k; return nil } }

// WithRegistry sets the messh registry base URL. Default: https://messh.io.
func WithRegistry(url string) Option {
	return func(c *Client) error {
		if !strings.HasPrefix(url, "https://") && !strings.HasPrefix(url, "http://") {
			return &Error{"invalid_option", "registry must be an http(s) URL"}
		}
		c.registry = strings.TrimRight(url, "/")
		return nil
	}
}

// WithExpiry sets how long a signature is valid. Default 60s, maximum 300s.
func WithExpiry(d time.Duration) Option {
	return func(c *Client) error {
		if d < time.Second || d > wba.MaxLifetime*time.Second {
			return &Error{"invalid_option", "expiry must be between 1s and 300s"}
		}
		c.expiresIn = d
		return nil
	}
}

// WithHTTPClient sets the client used by Do, Get and Post.
func WithHTTPClient(h *http.Client) Option { return func(c *Client) error { c.http = h; return nil } }

// WithClock and WithNonce make signatures reproducible in tests.
func WithClock(now func() time.Time) Option { return func(c *Client) error { c.now = now; return nil } }
func WithNonce(f func() string) Option      { return func(c *Client) error { c.nonce = f; return nil } }

// NewClient creates a client for identity, a messh username such as "mukul".
func NewClient(identity string, opts ...Option) (*Client, error) {
	if !identityRe.MatchString(identity) {
		return nil, &Error{"invalid_identity", fmt.Sprintf("%q is not a messh username", identity)}
	}
	home, _ := os.UserHomeDir()
	c := &Client{
		identity: identity, registry: DefaultRegistry, expiresIn: 60 * time.Second,
		key:  KeyFile(filepath.Join(home, ".ssh", "id_ed25519")),
		http: &http.Client{Timeout: 30 * time.Second}, now: time.Now, nonce: randomNonce,
	}
	for _, o := range opts {
		if err := o(c); err != nil {
			return nil, err
		}
	}
	s, err := c.key()
	if err != nil {
		return nil, err
	}
	c.signer = s
	return c, nil
}

func randomNonce() string {
	b := make([]byte, 16)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// NewClientFromEnv creates a client from the environment, for agents and CI:
// MESSH_IDENTITY (required), MESSH_KEY (PEM, or base64 of PEM or PKCS#8
// DER) or MESSH_KEY_FILE (default ~/.ssh/id_ed25519), and MESSH_REGISTRY.
// Options win over the environment.
func NewClientFromEnv(opts ...Option) (*Client, error) {
	identity := os.Getenv("MESSH_IDENTITY")
	if identity == "" {
		return nil, &Error{"invalid_identity", "set MESSH_IDENTITY to your messh username"}
	}
	var env []Option
	switch {
	case os.Getenv("MESSH_KEY") != "":
		env = append(env, WithKey(KeyEnv("MESSH_KEY")))
	case os.Getenv("MESSH_KEY_FILE") != "":
		env = append(env, WithKey(KeyFile(os.Getenv("MESSH_KEY_FILE"))))
	}
	if r := os.Getenv("MESSH_REGISTRY"); r != "" {
		env = append(env, WithRegistry(r))
	}
	return NewClient(identity, append(env, opts...)...)
}

// Agent is the Signature-Agent URL: <registry>/<identity>.
func (c *Client) Agent() string { return c.registry + "/" + c.identity }

// KeyID is the keyid sent in Signature-Input (RFC 7638 JWK thumbprint).
func (c *Client) KeyID() string { return wba.Thumbprint(c.signer.Public()) }

// Fingerprint is the signing key's SSH fingerprint (SHA256:…), as
// `messh keys` and ssh-keygen -l print it.
func (c *Client) Fingerprint() string { return wba.Fingerprint(c.signer.Public()) }

// PublishedKey is this client's key as messh lists it: what an API will see.
type PublishedKey struct {
	Identity    string // messh username, e.g. "mukul"
	KeyName     string // the key's name on messh, e.g. "build-bot"
	KeyID       string // RFC 7638 thumbprint, sent as keyid
	Fingerprint string // SHA256:… of the SSH key
	AgentURL    string // Signature-Agent: <registry>/<identity>
}

// WhoAmI checks that this client's key is published and active on messh, and
// how APIs will see it. Run it once at startup: it turns the most common
// setup mistake (an unpublished key, so every API answers 401 unknown_key)
// into a clear error: *Error with Code not_published or registry_unreachable.
func (c *Client) WhoAmI(ctx context.Context) (*PublishedKey, error) {
	u := c.Agent() + wba.DirectoryPath
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, &Error{"registry_unreachable", err.Error()}
	}
	req.Header.Set("Accept", "application/http-message-signatures-directory+json, application/json")
	req.Header.Set("User-Agent", "messh-go/"+Version)
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, &Error{"registry_unreachable", fmt.Sprintf("can't reach %s: %v", c.registry, err)}
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, &Error{"not_published", fmt.Sprintf("%s has no user %s; sign up, then publish this key (%s) with messh publish", c.registry, c.identity, c.Fingerprint())}
	}
	var dir wba.Directory
	if resp.StatusCode != http.StatusOK || json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&dir) != nil {
		return nil, &Error{"registry_unreachable", fmt.Sprintf("%s answered HTTP %d without a key directory", u, resp.StatusCode)}
	}
	for _, k := range dir.Keys {
		if k.Kid == c.KeyID() {
			fp := k.Fingerprint
			if fp == "" {
				fp = c.Fingerprint()
			}
			return &PublishedKey{Identity: c.identity, KeyName: k.Name, KeyID: k.Kid, Fingerprint: fp, AgentURL: c.Agent()}, nil
		}
	}
	return nil, &Error{"not_published", fmt.Sprintf("this key (%s) isn't an active key of %s; publish it with messh publish --key <key>.pub --name <name>", c.Fingerprint(), c.Agent())}
}

// Sign adds Signature-Agent, Signature-Input, Signature and, when there is a
// body, Content-Digest to req. Sign last: nothing may change the method,
// host, path, query or body afterwards.
func (c *Client) Sign(req *http.Request) error {
	agentHeader := strconv.Quote(c.Agent())
	req.Header.Set("Signature-Agent", agentHeader)
	host := req.Host
	if host == "" {
		host = req.URL.Host
	}
	path := req.URL.EscapedPath()
	if path == "" {
		path = "/"
	}
	comps := []wba.Component{
		{Name: "@method", Value: strings.ToUpper(req.Method)},
		{Name: "@authority", Value: strings.ToLower(host)},
		{Name: "@path", Value: path},
	}
	if req.URL.RawQuery != "" {
		comps = append(comps, wba.Component{Name: "@query", Value: "?" + req.URL.RawQuery})
	}
	if req.Body != nil && req.Body != http.NoBody {
		body, err := io.ReadAll(req.Body)
		req.Body.Close()
		if err != nil {
			return &Error{"sign_failed", "read body: " + err.Error()}
		}
		req.Body = io.NopCloser(bytes.NewReader(body))
		req.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(body)), nil }
		req.ContentLength = int64(len(body))
		digest := wba.ContentDigest(body)
		req.Header.Set("Content-Digest", digest)
		comps = append(comps, wba.Component{Name: "content-digest", Value: digest})
	}
	comps = append(comps, wba.Component{Name: "signature-agent", Value: agentHeader})

	names := make([]string, len(comps))
	for i, cp := range comps {
		names[i] = cp.Name
	}
	created := c.now().Unix()
	params := wba.Params(names, created, created+int64(c.expiresIn/time.Second), c.KeyID(), c.nonce())
	sig, err := c.signer.Sign(wba.Base(comps, params))
	if err != nil {
		return &Error{"sign_failed", err.Error()}
	}
	req.Header.Set("Signature-Input", wba.Label+"="+params)
	req.Header.Set("Signature", wba.Label+"=:"+base64.StdEncoding.EncodeToString(sig)+":")
	return nil
}

// Do signs and sends req.
func (c *Client) Do(req *http.Request) (*http.Response, error) {
	if err := c.Sign(req); err != nil {
		return nil, err
	}
	setUserAgent(req)
	return c.http.Do(req)
}

func setUserAgent(req *http.Request) {
	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", "messh-go/"+Version)
	}
}

// Get sends a signed GET.
func (c *Client) Get(url string) (*http.Response, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	return c.Do(req)
}

// Post sends a signed POST; the body is covered by Content-Digest.
func (c *Client) Post(url, contentType string, body io.Reader) (*http.Response, error) {
	req, err := http.NewRequest(http.MethodPost, url, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", contentType)
	return c.Do(req)
}

// Transport wraps base (nil = http.DefaultTransport) so every request
// through it is signed, e.g. &http.Client{Transport: client.Transport(nil)}.
func (c *Client) Transport(base http.RoundTripper) http.RoundTripper {
	if base == nil {
		base = http.DefaultTransport
	}
	return roundTripper(func(req *http.Request) (*http.Response, error) {
		req = req.Clone(req.Context())
		if err := c.Sign(req); err != nil {
			return nil, err
		}
		setUserAgent(req)
		return base.RoundTrip(req)
	})
}

type roundTripper func(*http.Request) (*http.Response, error)

func (f roundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
