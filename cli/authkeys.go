package main

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/crypto/ssh"
)

// akTarget is the authorized_keys file messh edits and who should own it.
type akTarget struct {
	path     string
	uid, gid int
}

func resolveTarget(unixUser, file string) (*akTarget, error) {
	t := &akTarget{uid: -1, gid: -1}
	switch {
	case file != "":
		t.path = file
	case unixUser != "":
		u, err := user.Lookup(unixUser)
		if err != nil {
			return nil, fmt.Errorf("unix user %q: %w", unixUser, err)
		}
		t.path = filepath.Join(u.HomeDir, ".ssh", "authorized_keys")
		t.uid, _ = strconv.Atoi(u.Uid)
		t.gid, _ = strconv.Atoi(u.Gid)
	default:
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, err
		}
		t.path = filepath.Join(home, ".ssh", "authorized_keys")
	}
	return t, nil
}

// akLine is one line of authorized_keys. tag is "" for lines messh didn't write.
type akLine struct {
	raw   string
	blob  string // "<type> <base64>", "" for comments and unparsable lines
	owner string // messh username from the tag
	tag   string
}

func parseLine(raw string) akLine {
	l := akLine{raw: raw}
	pk, comment, _, _, err := ssh.ParseAuthorizedKey([]byte(raw))
	if err != nil {
		return l
	}
	l.blob = strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pk)))
	if rest, ok := strings.CutPrefix(comment, "messh:"); ok {
		l.tag = comment
		l.owner, _, _ = strings.Cut(rest, "/")
	}
	return l
}

func tagFor(username, keyName string) string { return "messh:" + username + "/" + keyName }

// edit locks the .ssh directory, reads authorized_keys, applies fn, and
// writes the result atomically (temp file + rename) if anything changed.
func (t *akTarget) edit(fn func([]akLine) []akLine) error {
	dir := filepath.Dir(t.path)
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return permHint(err)
		}
		if t.uid >= 0 {
			os.Chown(dir, t.uid, t.gid)
		}
	}
	mode := os.FileMode(0o600)
	uid, gid := t.uid, t.gid

	d, err := os.Open(dir)
	if err != nil {
		return permHint(err)
	}
	defer d.Close()
	if err := syscall.Flock(int(d.Fd()), syscall.LOCK_EX); err != nil {
		return fmt.Errorf("lock %s: %w", dir, err)
	}
	defer syscall.Flock(int(d.Fd()), syscall.LOCK_UN)

	if fi, err := os.Stat(t.path); err == nil {
		mode = fi.Mode().Perm()
		if st, ok := fi.Sys().(*syscall.Stat_t); ok && uid < 0 {
			uid, gid = int(st.Uid), int(st.Gid)
		}
	}
	lines := readLines(t.path)
	before := joinLines(lines)
	after := joinLines(fn(lines))
	if after == before {
		return nil
	}

	tmp, err := os.CreateTemp(dir, ".authorized_keys.messh-*")
	if err != nil {
		return permHint(err)
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.WriteString(after); err != nil {
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		return err
	}
	if uid >= 0 && os.Geteuid() == 0 {
		if err := tmp.Chown(uid, gid); err != nil {
			return err
		}
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	tmp.Close()
	return permHint(os.Rename(tmp.Name(), t.path))
}

func readLines(path string) []akLine {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var out []akLine
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		out = append(out, parseLine(sc.Text()))
	}
	return out
}

func joinLines(lines []akLine) string {
	var b strings.Builder
	for _, l := range lines {
		b.WriteString(l.raw)
		b.WriteByte('\n')
	}
	return b.String()
}

func permHint(err error) error {
	if err != nil && os.IsPermission(err) {
		return fmt.Errorf("%w (try sudo)", err)
	}
	return err
}
