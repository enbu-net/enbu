//go:build linux

package keystore

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeCreds is a systemd-creds that "encrypts" by writing the name and the
// input, refuses to decrypt under another name, and logs its arguments.
func fakeCreds(t *testing.T) (*CredsBackend, string) {
	t.Helper()
	dir := t.TempDir()
	log := filepath.Join(dir, "args")
	script := `#!/bin/sh
echo "$*" >> ` + log + `
[ "$1" = --user ] || exit 2
name=$(printf '%s\n' "$@" | sed -n 's/^--name=//p')
case "$2" in
encrypt) printf 'name=%s\n' "$name"; cat ;;
decrypt)
	[ "$(head -n 1 "$4")" = "name=$name" ] || { echo "name mismatch" >&2; exit 1; }
	tail -n +2 "$4" ;;
*) exit 2 ;;
esac
`
	cmd := filepath.Join(dir, "systemd-creds")
	if err := os.WriteFile(cmd, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	return &CredsBackend{Dir: filepath.Join(dir, "credentials"), Command: cmd}, log
}

func TestCredsBackendRoundTrip(t *testing.T) {
	c, log := fakeCreds(t)
	if err := c.Probe(); err != nil {
		t.Fatal(err)
	}
	secret := []byte("AGE-SECRET-KEY-PQ-1EXAMPLE")
	if err := c.Store("enbu-identity-v1", "abc", secret); err != nil {
		t.Fatal(err)
	}
	got, err := c.Load("enbu-identity-v1", "abc")
	if err != nil || string(got) != string(secret) {
		t.Fatalf("Load = %q, %v", got, err)
	}
	st, err := os.Stat(c.Dir)
	if err != nil || st.Mode().Perm() != 0o700 {
		t.Fatalf("credentials directory: %v, %v", st, err)
	}
	args, err := os.ReadFile(log)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(args), string(secret)) {
		t.Fatal("the secret was passed as an argument")
	}

	// A file copied over another entry does not decrypt as that entry.
	if err := c.Store("enbu-identity-v1", "other", []byte("other")); err != nil {
		t.Fatal(err)
	}
	other, err := os.ReadFile(c.path("enbu-identity-v1", "other"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(c.path("enbu-identity-v1", "abc"), other, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Load("enbu-identity-v1", "abc"); err == nil || !strings.Contains(err.Error(), "name mismatch") {
		t.Fatalf("Load of a swapped file = %v", err)
	}

	if err := c.Delete("enbu-identity-v1", "abc"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Load("enbu-identity-v1", "abc"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("Load after Delete = %v", err)
	}
	if err := c.Delete("enbu-identity-v1", "abc"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("Delete of a missing entry = %v", err)
	}
}

func TestCredsBackendProbeFailsWithoutSystemdCreds(t *testing.T) {
	c := &CredsBackend{Dir: t.TempDir(), Command: filepath.Join(t.TempDir(), "missing")}
	if err := c.Probe(); err == nil {
		t.Fatal("Probe succeeded without systemd-creds")
	}
}
