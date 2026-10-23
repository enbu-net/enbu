package wsp

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/opencontainers/go-digest"
)

const trustRootVersion = 1

type trustRootFile struct {
	Version int           `json:"version"`
	Genesis digest.Digest `json:"genesis"`
}

// TrustRootChangedError means enbu.toml names a genesis other than the one this
// device first trusted for the workspace. Anyone who can change enbu.toml (a
// commit, a pull request, a checkout of another branch) could otherwise point
// the device at a Control they founded themselves and receive its secrets.
type TrustRootChangedError struct {
	Pinned     digest.Digest
	Configured digest.Digest
}

func (e *TrustRootChangedError) Error() string {
	return fmt.Sprintf("control genesis %s differs from the pinned %s", e.Configured, e.Pinned)
}

// TrustRoot pins, locally, the genesis a device first accepted for a
// workspace (trust on first use). Checkpoints are kept per genesis, so without
// the pin a new genesis would simply start an empty history.
type TrustRoot struct {
	path string
}

// OpenTrustRoot returns the pin of workspace under dir. The workspace is hashed
// so it cannot escape dir.
func OpenTrustRoot(dir, workspace string) *TrustRoot {
	sum := sha256.Sum256([]byte(workspace))
	return &TrustRoot{path: filepath.Join(dir, "trust-"+hex.EncodeToString(sum[:])+".json")}
}

// Pinned returns the pinned genesis, or "" when none is pinned yet.
func (t *TrustRoot) Pinned() (digest.Digest, error) {
	b, err := os.ReadFile(t.path)
	if errors.Is(err, fs.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	var f trustRootFile
	if err := json.Unmarshal(b, &f); err != nil || f.Version != trustRootVersion || validDigest(f.Genesis) != nil {
		return "", fmt.Errorf("corrupt trust root file %s", t.path)
	}
	return f.Genesis, nil
}

// Check returns a *TrustRootChangedError when another genesis is pinned.
func (t *TrustRoot) Check(genesis digest.Digest) error {
	pinned, err := t.Pinned()
	if err != nil {
		return err
	}
	if pinned != "" && pinned != genesis {
		return &TrustRootChangedError{Pinned: pinned, Configured: genesis}
	}
	return nil
}

// Pin records genesis when nothing is pinned. A different pinned genesis is
// kept and reported as a *TrustRootChangedError unless replace is set, which
// is how a person confirms that the workspace was really re-founded. It
// returns the genesis pinned before, or "".
func (t *TrustRoot) Pin(genesis digest.Digest, replace bool) (digest.Digest, error) {
	if err := validDigest(genesis); err != nil {
		return "", invalid("trusted genesis digest: %v", err)
	}
	release, err := lockFile(t.path)
	if err != nil {
		return "", err
	}
	defer release()
	pinned, err := t.Pinned()
	if err != nil && !replace {
		return "", err
	}
	if pinned == genesis {
		return pinned, nil
	}
	if pinned != "" && !replace {
		return pinned, &TrustRootChangedError{Pinned: pinned, Configured: genesis}
	}
	b, err := json.MarshalIndent(trustRootFile{Version: trustRootVersion, Genesis: genesis}, "", "  ")
	if err != nil {
		return "", err
	}
	return pinned, writeFileAtomic(t.path, b)
}
