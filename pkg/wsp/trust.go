package wsp

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/enbu-net/enbu/pkg/clock"
	"github.com/opencontainers/go-digest"
)

// Root is a trust root: a workspace and the digest of its genesis Control.
type Root struct {
	Workspace string        `json:"workspace"`
	Genesis   digest.Digest `json:"genesis"`
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

// PinMode says which existing pins Pin may replace.
type PinMode int

const (
	// PinFirst pins only what is not pinned yet; a different pin is an error.
	PinFirst PinMode = iota
	// PinFounded also moves the repository to the root: founding cannot hand
	// trust to anyone else. The workspace pin must still agree.
	PinFounded
	// PinReplace replaces both pins, after a person confirmed the workspace
	// was re-founded.
	PinReplace
)

type trustFile struct {
	// Workspaces maps a workspace ID to the genesis this device trusts for it,
	// wherever its enbu.toml is.
	Workspaces map[string]digest.Digest `json:"workspaces"`
	// Repositories maps the absolute path of an enbu.toml to the workspace it
	// uses. Both fields live in enbu.toml, so the workspace pin alone would let
	// a commit that changes the workspace ID as well start over with no pin.
	Repositories map[string]string `json:"repositories"`
}

// Trust pins, locally, the trust roots a device first accepted (trust on first
// use). Checkpoints are kept per genesis, so without the pin a new genesis
// would simply start an empty history. Every pin lives in one file, replaced
// as a whole, so the two kinds of pin never disagree after a crash.
type Trust struct {
	path  string
	clock clock.Clock
}

// OpenTrust returns the pins kept in dir.
func OpenTrust(dir string, c clock.Clock) *Trust {
	return &Trust{clock: c, path: filepath.Join(dir, "trust.json")}
}

// load reads the trust file. A file that is not a trust file at all is an
// error; an entry that does not hold a valid pin is kept as it is, and is an
// error only for the workspace or checkout it belongs to, so one damaged pin
// does not stop every other workspace on the device.
func (t *Trust) load() (trustFile, error) {
	f := trustFile{Workspaces: map[string]digest.Digest{}, Repositories: map[string]string{}}
	b, err := os.ReadFile(t.path)
	if errors.Is(err, fs.ErrNotExist) {
		return f, nil
	}
	if err != nil {
		return f, err
	}
	if json.Unmarshal(b, &f) != nil {
		return trustFile{}, fmt.Errorf("corrupt trust file %s", t.path)
	}
	if f.Workspaces == nil {
		f.Workspaces = map[string]digest.Digest{}
	}
	if f.Repositories == nil {
		f.Repositories = map[string]string{}
	}
	return f, nil
}

// checkWorkspace fails when the pin of workspace is present but invalid.
func (t *Trust) checkWorkspace(f trustFile, workspace string) error {
	if g, ok := f.Workspaces[workspace]; ok && (workspace == "" || validDigest(g) != nil) {
		return fmt.Errorf("corrupt pin of workspace %q in trust file %s; remove that entry and run enbu init again", workspace, t.path)
	}
	return nil
}

// checkRepository fails when the pin of the enbu.toml at repo, or of the
// workspace it names, is present but invalid.
func (t *Trust) checkRepository(f trustFile, repo string) error {
	ws, ok := f.Repositories[repo]
	if !ok {
		return nil
	}
	if repo == "" || ws == "" {
		return fmt.Errorf("corrupt pin of %q in trust file %s; remove that entry and run enbu init again", repo, t.path)
	}
	return t.checkWorkspace(f, ws)
}

// checkRoot fails when a pin that mode does not let root replace is invalid.
func (t *Trust) checkRoot(f trustFile, root Root, repo string, mode PinMode) error {
	if mode == PinReplace {
		return nil
	}
	if err := t.checkWorkspace(f, root.Workspace); err != nil {
		return err
	}
	if repo == "" || mode == PinFounded {
		return nil
	}
	return t.checkRepository(f, repo)
}

// Pinned returns the root pinned for workspace, or a zero Root.
func (t *Trust) Pinned(workspace string) (Root, error) {
	f, err := t.load()
	if err == nil {
		err = t.checkWorkspace(f, workspace)
	}
	if err != nil {
		return Root{}, err
	}
	return f.root(workspace), nil
}

// Repository returns the root pinned for the enbu.toml at repo: its workspace
// and the genesis pinned for that workspace, or a zero Root.
func (t *Trust) Repository(repo string) (Root, error) {
	f, err := t.load()
	if err == nil {
		err = t.checkRepository(f, repo)
	}
	if err != nil {
		return Root{}, err
	}
	ws, ok := f.Repositories[repo]
	if !ok {
		return Root{}, nil
	}
	return Root{Workspace: ws, Genesis: f.Workspaces[ws]}, nil
}

func (f trustFile) root(workspace string) Root {
	g, ok := f.Workspaces[workspace]
	if !ok {
		return Root{}
	}
	return Root{Workspace: workspace, Genesis: g}
}

// conflict returns the pinned root mode does not let root replace, or a zero
// Root. repo is the enbu.toml path, or "" when it is unknown.
func (f trustFile) conflict(root Root, repo string, mode PinMode) Root {
	if mode == PinReplace {
		return Root{}
	}
	if pinned := f.root(root.Workspace); pinned != (Root{}) && pinned != root {
		return pinned
	}
	if ws, ok := f.Repositories[repo]; ok && repo != "" && mode != PinFounded && ws != root.Workspace {
		return Root{Workspace: ws, Genesis: f.Workspaces[ws]}
	}
	return Root{}
}

// Check returns a *TrustRootChangedError when mode does not let root replace
// what is pinned.
func (t *Trust) Check(root Root, repo string, mode PinMode) error {
	if mode == PinReplace {
		return nil
	}
	f, err := t.load()
	if err == nil {
		err = t.checkRoot(f, root, repo, mode)
	}
	if err != nil {
		return err
	}
	if pinned := f.conflict(root, repo, mode); pinned != (Root{}) {
		return &TrustRootChangedError{Pinned: pinned, Configured: root}
	}
	return nil
}

// Pin records root for its workspace and for the enbu.toml at repo ("" when
// unknown), keeping and reporting a different pin as a *TrustRootChangedError
// unless mode lets it be replaced. It returns the different root that was
// pinned before, for the workspace or the repository, or a zero Root.
func (t *Trust) Pin(root Root, repo string, mode PinMode) (Root, error) {
	if root.Workspace == "" {
		return Root{}, invalid("trust root has no workspace")
	}
	if err := validDigest(root.Genesis); err != nil {
		return Root{}, invalid("trusted genesis digest: %v", err)
	}
	release, err := lockFile(t.path, t.clock)
	if err != nil {
		return Root{}, err
	}
	defer release()
	f, err := t.load()
	if err == nil {
		// Confirming a new root repairs only its own pins: the pins of other
		// workspaces and checkouts are written back as they were.
		err = t.checkRoot(f, root, repo, mode)
	}
	if err != nil {
		return Root{}, err
	}
	if pinned := f.conflict(root, repo, mode); pinned != (Root{}) {
		return pinned, &TrustRootChangedError{Pinned: pinned, Configured: root}
	}
	previous := f.root(root.Workspace)
	if previous == root {
		previous = Root{}
	}
	if ws, ok := f.Repositories[repo]; ok && repo != "" && ws != root.Workspace && previous == (Root{}) {
		previous = Root{Workspace: ws, Genesis: f.Workspaces[ws]}
	}
	changed := f.Workspaces[root.Workspace] != root.Genesis
	f.Workspaces[root.Workspace] = root.Genesis
	if repo != "" {
		changed = changed || f.Repositories[repo] != root.Workspace
		f.Repositories[repo] = root.Workspace
	}
	if !changed {
		return previous, nil
	}
	b, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return Root{}, err
	}
	return previous, writeFileAtomic(t.path, b)
}
