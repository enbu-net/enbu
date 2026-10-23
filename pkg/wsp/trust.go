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

// Root is a trust root: a workspace and the digest of its genesis Control.
type Root struct {
	Workspace string        `json:"workspace"`
	Genesis   digest.Digest `json:"genesis"`
}

type trustRootFile struct {
	Version int `json:"version"`
	Root
}

// TrustRootChangedError means enbu.toml names a trust root other than the one
// this device first accepted. Anyone who can change enbu.toml (a commit, a pull
// request, a checkout of another branch) could otherwise point the device at a
// Control they founded themselves and receive its secrets.
type TrustRootChangedError struct {
	Pinned     Root
	Configured Root
}

func (e *TrustRootChangedError) Error() string {
	if e.Pinned.Workspace != e.Configured.Workspace {
		return fmt.Sprintf("workspace %s differs from the pinned %s", e.Configured.Workspace, e.Pinned.Workspace)
	}
	return fmt.Sprintf("control genesis %s differs from the pinned %s", e.Configured.Genesis, e.Pinned.Genesis)
}

// TrustRoot pins, locally, the trust root a device first accepted (trust on
// first use). Checkpoints are kept per genesis, so without the pin a new
// genesis would simply start an empty history.
type TrustRoot struct {
	path string
}

// OpenTrustRoot returns the pin of workspace under dir: the genesis this device
// trusts for that workspace ID, wherever its enbu.toml is.
func OpenTrustRoot(dir, workspace string) *TrustRoot {
	return openTrustRoot(dir, "trust-", workspace)
}

// OpenRepositoryTrustRoot returns the pin of the enbu.toml at configPath: the
// workspace and genesis this repository checkout uses. Both fields live in
// enbu.toml, so the workspace pin alone would let a commit that changes the
// workspace ID as well start over with no pin at all.
func OpenRepositoryTrustRoot(dir, configPath string) *TrustRoot {
	return openTrustRoot(dir, "repo-", configPath)
}

// openTrustRoot hashes key so it cannot escape dir.
func openTrustRoot(dir, prefix, key string) *TrustRoot {
	sum := sha256.Sum256([]byte(key))
	return &TrustRoot{path: filepath.Join(dir, prefix+hex.EncodeToString(sum[:])+".json")}
}

// Pinned returns the pinned root, or a zero Root when none is pinned yet.
func (t *TrustRoot) Pinned() (Root, error) {
	b, err := os.ReadFile(t.path)
	if errors.Is(err, fs.ErrNotExist) {
		return Root{}, nil
	}
	if err != nil {
		return Root{}, err
	}
	var f trustRootFile
	if err := json.Unmarshal(b, &f); err != nil || f.Version != trustRootVersion || f.Workspace == "" || validDigest(f.Genesis) != nil {
		return Root{}, fmt.Errorf("corrupt trust root file %s", t.path)
	}
	return f.Root, nil
}

// Check returns a *TrustRootChangedError when another root is pinned.
func (t *TrustRoot) Check(root Root) error {
	pinned, err := t.Pinned()
	if err != nil {
		return err
	}
	if pinned != (Root{}) && pinned != root {
		return &TrustRootChangedError{Pinned: pinned, Configured: root}
	}
	return nil
}

// Pin records root when nothing is pinned. A different pinned root is kept
// and reported as a *TrustRootChangedError unless replace is set, which is how
// a person confirms that the workspace was really re-founded. It returns the
// root pinned before, or a zero Root.
func (t *TrustRoot) Pin(root Root, replace bool) (Root, error) {
	if root.Workspace == "" {
		return Root{}, invalid("trust root has no workspace")
	}
	if err := validDigest(root.Genesis); err != nil {
		return Root{}, invalid("trusted genesis digest: %v", err)
	}
	release, err := lockFile(t.path)
	if err != nil {
		return Root{}, err
	}
	defer release()
	pinned, err := t.Pinned()
	if err != nil && !replace {
		return Root{}, err
	}
	if pinned == root {
		return pinned, nil
	}
	if pinned != (Root{}) && !replace {
		return pinned, &TrustRootChangedError{Pinned: pinned, Configured: root}
	}
	b, err := json.MarshalIndent(trustRootFile{Version: trustRootVersion, Root: root}, "", "  ")
	if err != nil {
		return Root{}, err
	}
	return pinned, writeFileAtomic(t.path, b)
}
