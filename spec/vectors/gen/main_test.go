package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"os"
	"testing"

	"golang.org/x/crypto/ssh"
)

// The OpenSSH key file can't be compared byte for byte (ssh.MarshalPrivateKey
// writes random check bytes each time), so check that it holds the vector key.
func TestOpenSSHKeyFile(t *testing.T) {
	b, err := os.ReadFile("../test_ed25519")
	if err != nil {
		t.Fatal(err)
	}
	k, err := ssh.ParseRawPrivateKey(b)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := k.(*ed25519.PrivateKey)
	seed := sha256.Sum256([]byte(keySeed))
	if !ok || !ed25519.NewKeyFromSeed(seed[:]).Equal(*got) {
		t.Fatalf("spec/vectors/test_ed25519 is not the vector key (got %T)", k)
	}
}
