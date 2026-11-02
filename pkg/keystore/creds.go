package keystore

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/enbu-net/enbu/pkg/fsutil"
)

// CredsBackend keeps each secret in a file encrypted with
// `systemd-creds --user` (systemd 256 or later). systemd binds the file to
// this user and to the machine: to the host key in /var/lib/systemd, and also
// to the TPM when there is one, which the user does not need access to. It is
// the fallback for Linux without a Secret Service, such as a server, a
// container or WSL. The secret passes through stdin and stdout only.
type CredsBackend struct {
	Dir string
	// Command is the systemd-creds executable; tests replace it.
	Command string
}

const credsTimeout = 10 * time.Second

func (c *CredsBackend) command() string {
	if c.Command != "" {
		return c.Command
	}
	return "systemd-creds"
}

// Probe encrypts a throwaway value, which fails before systemd 256, without
// the user's credential service, or without a host key.
func (c *CredsBackend) Probe() error {
	_, err := c.run([]byte("probe"), "encrypt", "--name=enbu-probe", "-", "-")
	return err
}

func (c *CredsBackend) Store(service, key string, secret []byte) error {
	path := c.path(service, key)
	if err := os.MkdirAll(c.Dir, 0o700); err != nil {
		return fmt.Errorf("creating credentials directory: %w", err)
	}
	sealed, err := c.run(secret, "encrypt", "--name="+credName(service, key), "-", "-")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(c.Dir, ".cred-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if _, err = tmp.Write(sealed); err == nil {
		err = tmp.Sync()
	}
	if err = errors.Join(err, tmp.Close()); err != nil {
		return err
	}
	return fsutil.Rename(tmp.Name(), path)
}

func (c *CredsBackend) Load(service, key string) ([]byte, error) {
	path := c.path(service, key)
	if _, err := os.Stat(path); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, fs.ErrNotExist
		}
		return nil, err
	}
	// The name is checked on decryption, so a file copied over another
	// entry's does not decrypt as that entry.
	return c.run(nil, "decrypt", "--name="+credName(service, key), path, "-")
}

func (c *CredsBackend) Delete(service, key string) error {
	if err := os.Remove(c.path(service, key)); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return fs.ErrNotExist
		}
		return err
	}
	return nil
}

func (c *CredsBackend) path(service, key string) string {
	return filepath.Join(c.Dir, service+"_"+sanitizeKey(key)+".cred")
}

func credName(service, key string) string { return service + "." + sanitizeKey(key) }

func (c *CredsBackend) run(stdin []byte, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), credsTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, c.command(), append([]string{"--user"}, args...)...)
	cmd.Stdin = bytes.NewReader(stdin)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		if msg := strings.TrimSpace(stderr.String()); msg != "" {
			return nil, fmt.Errorf("systemd-creds %s: %w: %s", args[0], err, msg)
		}
		return nil, fmt.Errorf("systemd-creds %s: %w", args[0], err)
	}
	return stdout.Bytes(), nil
}
