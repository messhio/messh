package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func pubLine(t *testing.T) string {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	k, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(k)))
}

func TestParseLineTags(t *testing.T) {
	key := pubLine(t)
	l := parseLine(key + " " + tagFor("mukul", "laptop"))
	if l.owner != "mukul" || l.tag != "messh:mukul/laptop" || l.blob != key {
		t.Fatalf("tagged line: %+v", l)
	}
	if l := parseLine(key + " ops@hand-added"); l.tag != "" || l.owner != "" || l.blob != key {
		t.Fatalf("hand-added line: %+v", l)
	}
	if l := parseLine("# a comment"); l.blob != "" || l.tag != "" {
		t.Fatalf("comment: %+v", l)
	}
}

// edit must only change what fn changes, keep the file mode, and write atomically.
func TestEditKeepsUntaggedLinesAndMode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".ssh", "authorized_keys")
	os.MkdirAll(filepath.Dir(path), 0o700)
	hand := pubLine(t) + " ops@hand-added"
	os.WriteFile(path, []byte("# keep me\n"+hand+"\n"), 0o640)
	tgt := &akTarget{path: path, uid: -1, gid: -1}

	add := pubLine(t) + " " + tagFor("mukul", "laptop")
	if err := tgt.edit(func(ls []akLine) []akLine { return append(ls, parseLine(add)) }); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(path)
	if got := string(b); got != "# keep me\n"+hand+"\n"+add+"\n" {
		t.Fatalf("after add:\n%s", got)
	}
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o640 {
		t.Fatalf("mode changed to %v", fi.Mode().Perm())
	}

	// Removing mukul's lines leaves the comment and the hand-added key.
	err := tgt.edit(func(ls []akLine) []akLine {
		out := ls[:0]
		for _, l := range ls {
			if l.owner != "mukul" {
				out = append(out, l)
			}
		}
		return out
	})
	if err != nil {
		t.Fatal(err)
	}
	b, _ = os.ReadFile(path)
	if got := string(b); got != "# keep me\n"+hand+"\n" {
		t.Fatalf("after remove:\n%s", got)
	}
	if left, _ := filepath.Glob(filepath.Join(dir, ".ssh", ".authorized_keys.messh-*")); len(left) != 0 {
		t.Fatalf("temp files left behind: %v", left)
	}
}

func TestEditCreatesSSHDir(t *testing.T) {
	path := filepath.Join(t.TempDir(), "home", ".ssh", "authorized_keys")
	tgt := &akTarget{path: path, uid: -1, gid: -1}
	line := pubLine(t) + " " + tagFor("mukul", "devbox")
	if err := tgt.edit(func(ls []akLine) []akLine { return append(ls, parseLine(line)) }); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(filepath.Dir(path)); err != nil || fi.Mode().Perm() != 0o700 {
		t.Fatalf(".ssh dir: %v %v", fi, err)
	}
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o600 {
		t.Fatalf("new authorized_keys mode %v", fi.Mode().Perm())
	}
}
