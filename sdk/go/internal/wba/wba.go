// Package wba holds the Web Bot Auth constants and key formats shared by the
// client and the verifier: key directories, RFC 7638 thumbprints, SSH
// fingerprints and RFC 9530 Content-Digest. Signatures are package httpsig.
package wba

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
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
