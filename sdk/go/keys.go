package messh

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"messh.io/go/messh/internal/wba"
)

// Signer signs with an Ed25519 key. Implement it to keep keys in a KMS,
// HSM or ssh-agent; the SDK never needs the key bytes.
type Signer interface {
	Public() ed25519.PublicKey
	Sign(message []byte) ([]byte, error)
}

// KeySource produces the Signer a Client uses.
type KeySource func() (Signer, error)

// seedSigner holds key material in memory. Format keeps it out of logs.
type seedSigner struct{ k ed25519.PrivateKey }

func (s seedSigner) Format(f fmt.State, _ rune) { f.Write([]byte("messh.Signer(ed25519)")) }

func (s seedSigner) Public() ed25519.PublicKey     { return s.k.Public().(ed25519.PublicKey) }
func (s seedSigner) Sign(m []byte) ([]byte, error) { return ed25519.Sign(s.k, m), nil }
func newSeedSigner(seed []byte) seedSigner         { return seedSigner{ed25519.NewKeyFromSeed(seed)} }
func keyErr(format string, a ...any) error {
	return &Error{Code: "invalid_key", Message: fmt.Sprintf(format, a...)}
}

// KeyFile loads an unencrypted ssh-ed25519 OpenSSH private key or a PKCS#8
// PEM Ed25519 key, e.g. ~/.ssh/id_ed25519 — the key you published with
// `messh publish`. A leading ~/ is your home directory.
func KeyFile(path string) KeySource {
	return func() (Signer, error) {
		p := path
		if rest, ok := strings.CutPrefix(p, "~/"); ok {
			if home, err := os.UserHomeDir(); err == nil {
				p = filepath.Join(home, rest)
			}
		}
		b, err := os.ReadFile(p)
		if errors.Is(err, fs.ErrNotExist) {
			return nil, keyErr("read %s: no such file; create one with ssh-keygen -t ed25519, then messh publish", path)
		}
		if err != nil {
			return nil, keyErr("read %s: %v", path, err)
		}
		return parseKey(b)
	}
}

// SSHAgent uses a key held by ssh-agent (SSH_AUTH_SOCK), such as a
// passphrase-protected key you added with ssh-add. The private key stays in
// the agent. With several Ed25519 keys loaded, pass the fingerprint
// (SHA256:…) of the one you published; "" picks the only one.
func SSHAgent(fingerprint string) KeySource {
	return func() (Signer, error) {
		path := os.Getenv("SSH_AUTH_SOCK")
		if path == "" && runtime.GOOS == "windows" {
			path = `\\.\pipe\openssh-ssh-agent`
		}
		if path == "" {
			return nil, keyErr(`ssh-agent isn't running (SSH_AUTH_SOCK is not set); start it: eval "$(ssh-agent)" && ssh-add`)
		}
		reply, err := agentCall(path, []byte{agentcRequestIdentities})
		if err == nil && (len(reply) == 0 || reply[0] != agentIdentitiesAnswer) {
			err = errors.New("it wouldn't list its keys")
		}
		if err != nil {
			return nil, keyErr("ssh-agent at %s: %v", path, err)
		}
		type agentKey struct {
			blob []byte
			pub  ed25519.PublicKey
			fp   string
		}
		var keys []agentKey
		r := &reader{b: reply[1:]}
		for n := r.u32(); n > 0 && r.err == nil; n-- {
			blob := r.str()
			r.str() // comment
			b := &reader{b: blob}
			if string(b.str()) != "ssh-ed25519" {
				continue
			}
			if pub := b.str(); b.err == nil && len(pub) == ed25519.PublicKeySize {
				keys = append(keys, agentKey{blob, ed25519.PublicKey(pub), wba.Fingerprint(pub)})
			}
		}
		if r.err != nil {
			return nil, keyErr("ssh-agent at %s: malformed reply", path)
		}
		fps := make([]string, len(keys))
		for i, k := range keys {
			fps[i] = k.fp
		}
		pick := keys
		if fingerprint != "" {
			pick = nil
			for _, k := range keys {
				if k.fp == fingerprint {
					pick = append(pick, k)
				}
			}
		}
		switch {
		case len(keys) == 0:
			return nil, keyErr("ssh-agent has no Ed25519 keys; add yours with ssh-add ~/.ssh/id_ed25519")
		case len(pick) == 0:
			return nil, keyErr("ssh-agent has no key %s; it has %s", fingerprint, strings.Join(fps, ", "))
		case len(pick) > 1:
			return nil, keyErr("ssh-agent has %d Ed25519 keys; choose one with SSHAgent(fingerprint): %s", len(keys), strings.Join(fps, ", "))
		}
		return agentSigner{path: path, blob: pick[0].blob, pub: pick[0].pub}, nil
	}
}

// ssh-agent protocol (draft-miller-ssh-agent): uint32 length, message type, payload.
const (
	agentcRequestIdentities = 11
	agentIdentitiesAnswer   = 12
	agentcSignRequest       = 13
	agentSignResponse       = 14
)

type agentSigner struct {
	path string
	blob []byte
	pub  ed25519.PublicKey
}

func (s agentSigner) Format(f fmt.State, _ rune) { f.Write([]byte("messh.Signer(ssh-agent)")) }
func (s agentSigner) Public() ed25519.PublicKey  { return s.pub }

func (s agentSigner) Sign(m []byte) ([]byte, error) {
	msg := append([]byte{agentcSignRequest}, wba.SSHString(s.blob)...)
	msg = append(append(msg, wba.SSHString(m)...), 0, 0, 0, 0)
	reply, err := agentCall(s.path, msg)
	if err != nil {
		return nil, fmt.Errorf("ssh-agent: %w", err)
	}
	if len(reply) == 0 || reply[0] != agentSignResponse {
		return nil, errors.New("ssh-agent refused to sign; is the key still loaded (ssh-add -l)?")
	}
	sig := &reader{b: (&reader{b: reply[1:]}).str()}
	if string(sig.str()) != "ssh-ed25519" {
		return nil, errors.New("ssh-agent returned an unexpected signature")
	}
	raw := sig.str()
	if sig.err != nil || len(raw) != ed25519.SignatureSize {
		return nil, errors.New("ssh-agent returned an unexpected signature")
	}
	return raw, nil
}

func agentCall(path string, msg []byte) ([]byte, error) {
	var conn io.ReadWriteCloser
	var err error
	if strings.HasPrefix(path, `\\.\pipe\`) {
		conn, err = os.OpenFile(path, os.O_RDWR, 0)
	} else {
		var c net.Conn
		c, err = net.DialTimeout("unix", path, 5*time.Second)
		if err == nil {
			c.SetDeadline(time.Now().Add(30 * time.Second))
		}
		conn = c
	}
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if _, err := conn.Write(wba.SSHString(msg)); err != nil {
		return nil, err
	}
	var n [4]byte
	if _, err := io.ReadFull(conn, n[:]); err != nil {
		return nil, err
	}
	reply := make([]byte, binary.BigEndian.Uint32(n[:]))
	if _, err := io.ReadFull(conn, reply); err != nil {
		return nil, err
	}
	return reply, nil
}

// KeyEnv reads a key from an environment variable: PEM text (OpenSSH or
// PKCS#8), or base64 of either PEM or PKCS#8 DER.
func KeyEnv(name string) KeySource {
	return func() (Signer, error) {
		v := strings.TrimSpace(os.Getenv(name))
		if v == "" {
			return nil, keyErr("environment variable %s is empty", name)
		}
		if !strings.Contains(v, "-----BEGIN") {
			b, err := base64.StdEncoding.DecodeString(v)
			if err != nil {
				return nil, keyErr("%s is neither PEM nor base64", name)
			}
			if !bytes.Contains(b, []byte("-----BEGIN")) {
				return parsePKCS8(b)
			}
			v = string(b)
		}
		return parseKey([]byte(v))
	}
}

// KeySeed uses a raw 32-byte Ed25519 seed.
func KeySeed(seed []byte) KeySource {
	return func() (Signer, error) {
		if len(seed) != ed25519.SeedSize {
			return nil, keyErr("seed must be %d bytes", ed25519.SeedSize)
		}
		return newSeedSigner(seed), nil
	}
}

// KeySigner uses your own Signer (KMS, HSM, ssh-agent).
func KeySigner(s Signer) KeySource {
	return func() (Signer, error) {
		if s == nil || len(s.Public()) != ed25519.PublicKeySize {
			return nil, keyErr("signer has no Ed25519 public key")
		}
		return s, nil
	}
}

func parseKey(b []byte) (Signer, error) {
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, keyErr("no PEM block")
	}
	switch block.Type {
	case "OPENSSH PRIVATE KEY":
		return parseOpenSSH(block.Bytes)
	case "PRIVATE KEY":
		return parsePKCS8(block.Bytes)
	case "ENCRYPTED PRIVATE KEY":
		return nil, keyErr("encrypted keys aren't supported; load the key into ssh-agent and use SSHAgent")
	}
	return nil, keyErr("unsupported PEM type %q", block.Type)
}

func parsePKCS8(der []byte) (Signer, error) {
	k, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, keyErr("PKCS#8: %v", err)
	}
	ek, ok := k.(ed25519.PrivateKey)
	if !ok {
		return nil, keyErr("PKCS#8 key is not Ed25519")
	}
	return seedSigner{ek}, nil
}

// parseOpenSSH reads the openssh-key-v1 container (PROTOCOL.key).
func parseOpenSSH(b []byte) (Signer, error) {
	const magic = "openssh-key-v1\x00"
	if !bytes.HasPrefix(b, []byte(magic)) {
		return nil, keyErr("not an OpenSSH private key")
	}
	r := &reader{b: b[len(magic):]}
	cipher, _, _ := r.str(), r.str(), r.str()
	if string(cipher) != "none" {
		return nil, keyErr("passphrase-protected key; load it into ssh-agent (ssh-add) and use SSHAgent")
	}
	if n := r.u32(); n != 1 {
		return nil, keyErr("expected one key, found %d", n)
	}
	r.str() // public key blob
	p := &reader{b: r.str()}
	if r.err != nil {
		return nil, keyErr("truncated OpenSSH key")
	}
	if p.u32() != p.u32() {
		return nil, keyErr("OpenSSH key check bytes differ (wrong passphrase?)")
	}
	if t := string(p.str()); t != "ssh-ed25519" {
		return nil, keyErr("need an ssh-ed25519 key, got %s", t)
	}
	pub, sk := p.str(), p.str()
	if p.err != nil || len(sk) != ed25519.PrivateKeySize || !bytes.Equal(sk[32:], pub) {
		return nil, keyErr("malformed ssh-ed25519 private key")
	}
	return newSeedSigner(sk[:32]), nil
}

type reader struct {
	b   []byte
	err error
}

func (r *reader) u32() uint32 {
	if len(r.b) < 4 {
		r.err = errors.New("short")
		return 0
	}
	v := binary.BigEndian.Uint32(r.b)
	r.b = r.b[4:]
	return v
}

func (r *reader) str() []byte {
	n := int(r.u32())
	if r.err != nil || n > len(r.b) {
		r.err = errors.New("short")
		return nil
	}
	s := r.b[:n]
	r.b = r.b[n:]
	return s
}
