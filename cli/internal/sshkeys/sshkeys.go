// Package sshkeys checks public keys before the CLI uploads them.
package sshkeys

import (
	"bytes"
	"errors"
	"strings"

	"golang.org/x/crypto/ssh"
)

// Key is a parsed public key.
type Key struct {
	Type        string
	Fingerprint string
	Line        string // "<type> <base64>", no comment
}

// LooksPrivate reports whether data holds a private key in any known format.
func LooksPrivate(data []byte) bool {
	if bytes.Contains(data, []byte("PRIVATE KEY")) {
		return true
	}
	_, err := ssh.ParseRawPrivateKey(data)
	var missing *ssh.PassphraseMissingError
	return err == nil || errors.As(err, &missing)
}

// ParsePublic parses one authorized_keys-format public key.
func ParsePublic(data []byte) (*Key, error) {
	if LooksPrivate(data) {
		return nil, errors.New("this looks like a private key; publish the .pub file")
	}
	pk, _, _, rest, err := ssh.ParseAuthorizedKey(data)
	if err != nil {
		return nil, errors.New("not an OpenSSH public key")
	}
	if len(bytes.TrimSpace(rest)) > 0 {
		return nil, errors.New("expected exactly one public key")
	}
	return &Key{Type: pk.Type(), Fingerprint: ssh.FingerprintSHA256(pk), Line: strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pk)))}, nil
}
