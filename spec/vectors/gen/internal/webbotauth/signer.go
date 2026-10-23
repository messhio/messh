package webbotauth

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
)

type keySigner struct{ priv ed25519.PrivateKey }

func (k keySigner) Public() ed25519.PublicKey        { return k.priv.Public().(ed25519.PublicKey) }
func (k keySigner) Sign(data []byte) ([]byte, error) { return ed25519.Sign(k.priv, data), nil }

type agentSigner struct {
	ag  agent.ExtendedAgent
	key ssh.PublicKey
	pub ed25519.PublicKey
}

func (a agentSigner) Public() ed25519.PublicKey { return a.pub }

// Sign asks ssh-agent to sign; for ssh-ed25519 the blob is a plain Ed25519 signature.
func (a agentSigner) Sign(data []byte) ([]byte, error) {
	sig, err := a.ag.Sign(a.key, data)
	if err != nil {
		return nil, err
	}
	return sig.Blob, nil
}

// LoadSigner uses the ssh-ed25519 key at pubPath: through ssh-agent if it
// holds the key, else from the private key file next to it. The private key
// is only read locally; it never leaves the machine.
func LoadSigner(pubPath string) (Signer, error) {
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
	pub := ed25519.PublicKey(pk.(ssh.CryptoPublicKey).CryptoPublicKey().(ed25519.PublicKey))

	if sock := os.Getenv("SSH_AUTH_SOCK"); sock != "" {
		if conn, err := net.Dial("unix", sock); err == nil {
			ag := agent.NewClient(conn)
			if keys, err := ag.List(); err == nil {
				for _, k := range keys {
					if bytes.Equal(k.Marshal(), pk.Marshal()) {
						return agentSigner{ag: ag, key: pk, pub: pub}, nil
					}
				}
			}
			conn.Close()
		}
	}

	privData, err := os.ReadFile(strings.TrimSuffix(pubPath, ".pub"))
	if err != nil {
		return nil, fmt.Errorf("key not in ssh-agent and no private key file: %w", err)
	}
	raw, err := ssh.ParseRawPrivateKey(privData)
	var missing *ssh.PassphraseMissingError
	if errors.As(err, &missing) {
		return nil, errors.New("the private key has a passphrase; load it with ssh-add first")
	}
	if err != nil {
		return nil, err
	}
	priv, ok := raw.(*ed25519.PrivateKey)
	if !ok || !bytes.Equal(priv.Public().(ed25519.PublicKey), pub) {
		return nil, errors.New("private key doesn't match " + pubPath)
	}
	return keySigner{priv: *priv}, nil
}
