package main

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"messh.io/go/messh"
)

// agentSigner signs through ssh-agent; for ssh-ed25519 the signature blob is
// a plain Ed25519 signature, which is what Web Bot Auth needs.
type agentSigner struct {
	ag  agent.ExtendedAgent
	key ssh.PublicKey
	pub ed25519.PublicKey
}

func (a agentSigner) Public() ed25519.PublicKey { return a.pub }

func (a agentSigner) Sign(data []byte) ([]byte, error) {
	sig, err := a.ag.Sign(a.key, data)
	if err != nil {
		return nil, err
	}
	return sig.Blob, nil
}

// signingKey uses the ssh-ed25519 key at pubPath: via ssh-agent if it holds
// it, else the private key file next to it. The key never leaves this machine.
func signingKey(pubPath string) (messh.KeySource, error) {
	data, err := os.ReadFile(pubPath)
	if err != nil {
		return nil, err
	}
	pk, _, _, _, err := ssh.ParseAuthorizedKey(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", pubPath, err)
	}
	if pk.Type() != ssh.KeyAlgoED25519 {
		return nil, fmt.Errorf("%s is %s; Web Bot Auth needs an ssh-ed25519 key", pubPath, pk.Type())
	}
	pub := pk.(ssh.CryptoPublicKey).CryptoPublicKey().(ed25519.PublicKey)
	if sock := os.Getenv("SSH_AUTH_SOCK"); sock != "" {
		if conn, err := net.Dial("unix", sock); err == nil {
			ag := agent.NewClient(conn)
			if list, err := ag.List(); err == nil {
				for _, k := range list {
					if bytes.Equal(k.Marshal(), pk.Marshal()) {
						return messh.KeySigner(agentSigner{ag: ag, key: pk, pub: pub}), nil
					}
				}
			}
			conn.Close()
		}
	}
	priv := strings.TrimSuffix(pubPath, ".pub")
	if priv == pubPath {
		return nil, errors.New("pass the .pub path; the private key next to it signs locally")
	}
	return messh.KeyFile(priv), nil
}
