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
	"sync"
	"time"

	"github.com/opencontainers/go-digest"
)

// checkpointVersion is the on-disk format. Files of an older format held a
// single digest per object and are not carried over: they start empty.
const checkpointVersion = 2

type checkpointFile struct {
	Version int                        `json:"version"`
	Control []digest.Digest            `json:"control,omitempty"`
	States  map[string][]digest.Digest `json:"states,omitempty"`
}

// Checkpoints persists the heads a client has accepted, locally only, so
// storage cannot later show less than it already showed. It needs no server.
// A head is an anchor, not an order: a later view must still contain every
// accepted head, as itself or as an ancestor, and may add newer revisions.
//
// Every update is a read-modify-write under an OS file lock, so concurrent
// processes cannot overwrite each other.
type Checkpoints struct {
	path string
	mu   sync.Mutex
}

// OpenCheckpoints returns the checkpoint file for a workspace under dir. A
// checkpoint belongs to one trust root, so the genesis digest is part of the
// name: pointing the same workspace at a different genesis starts a separate
// history instead of being mistaken for a rollback. Both values are hashed so
// they cannot escape dir.
func OpenCheckpoints(dir, workspace string, genesis digest.Digest) *Checkpoints {
	sum := sha256.Sum256([]byte(workspace + "\x00" + string(genesis)))
	return &Checkpoints{path: filepath.Join(dir, hex.EncodeToString(sum[:])+".json")}
}

func (c *Checkpoints) read() (checkpointFile, error) {
	b, err := os.ReadFile(c.path)
	if errors.Is(err, fs.ErrNotExist) {
		return checkpointFile{Version: checkpointVersion}, nil
	}
	if err != nil {
		return checkpointFile{}, err
	}
	var v struct {
		Version int `json:"version"`
	}
	if err := json.Unmarshal(b, &v); err != nil || v.Version < 1 || v.Version > checkpointVersion {
		return checkpointFile{}, fmt.Errorf("corrupt checkpoint file %s", c.path)
	}
	if v.Version < checkpointVersion {
		return checkpointFile{Version: checkpointVersion}, nil
	}
	var f checkpointFile
	if err := json.Unmarshal(b, &f); err != nil {
		return checkpointFile{}, fmt.Errorf("corrupt checkpoint file %s", c.path)
	}
	return f, nil
}

func (c *Checkpoints) write(f checkpointFile) error {
	b, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(c.path, b)
}

const lockTimeout = 5 * time.Second

// lockFile takes an exclusive OS lock on path+".lock", waiting up to
// lockTimeout, and returns the function that releases it.
func lockFile(path string) (func(), error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	lock, err := os.OpenFile(path+".lock", os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	deadline := time.Now().Add(lockTimeout)
	for {
		ok, err := tryLock(lock)
		if err != nil {
			_ = lock.Close()
			return nil, err
		}
		if ok {
			return func() { unlock(lock); _ = lock.Close() }, nil
		}
		if time.Now().After(deadline) {
			_ = lock.Close()
			return nil, fmt.Errorf("timed out waiting for the lock %s.lock", path)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// writeFileAtomic replaces path with b through a synced temporary file.
func writeFileAtomic(path string, b []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".checkpoint-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if _, err = tmp.Write(b); err == nil {
		err = tmp.Sync()
	}
	if err = errors.Join(err, tmp.Close()); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// update runs fn on the current contents while holding the file lock, and
// writes the result back if fn reports a change.
func (c *Checkpoints) update(fn func(*checkpointFile) (bool, error)) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	release, err := lockFile(c.path)
	if err != nil {
		return err
	}
	defer release()
	f, err := c.read()
	if err != nil {
		return err
	}
	changed, err := fn(&f)
	if err != nil || !changed {
		return err
	}
	return c.write(f)
}

// Control returns the accepted Control heads, or nil if none.
func (c *Checkpoints) Control() ([]digest.Digest, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	f, err := c.read()
	return f.Control, err
}

// State returns the accepted heads of resource, or nil if none.
func (c *Checkpoints) State(resource string) ([]digest.Digest, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	f, err := c.read()
	return f.States[resource], err
}

// missingFrom returns the first accepted head that the view no longer holds.
func missingFrom(accepted []digest.Digest, has func(digest.Digest) bool) (digest.Digest, bool) {
	for _, d := range accepted {
		if !has(d) {
			return d, true
		}
	}
	return "", false
}

func sameDigests(a, b []digest.Digest) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// AcceptControl records the heads of view as accepted. The view must still
// contain every previously accepted head; a view that does not is storage
// showing an older Control DAG than this client saw.
func (c *Checkpoints) AcceptControl(view *ControlView) error {
	heads := make([]digest.Digest, len(view.Heads))
	for i, h := range view.Heads {
		heads[i] = h.Digest
	}
	return c.update(func(f *checkpointFile) (bool, error) {
		if d, gone := missingFrom(f.Control, func(d digest.Digest) bool { _, ok := view.Get(d); return ok }); gone {
			return false, fmt.Errorf("%w: accepted control %s is missing from storage", ErrRollback, d)
		}
		if sameDigests(f.Control, heads) {
			return false, nil
		}
		f.Control = heads
		return true, nil
	})
}

// CheckStates rejects a view of resource that lacks a head this client
// accepted, unless excused reports that a compaction removed it. excused may
// be nil. It does not record anything.
func (c *Checkpoints) CheckStates(resource string, g *Graph, excused func(digest.Digest) bool) error {
	accepted, err := c.State(resource)
	if err != nil {
		return err
	}
	if d, gone := missingFrom(accepted, shownOrExcused(g, excused)); gone {
		return fmt.Errorf("%w: %s revision %s is missing from storage", ErrRollback, resource, d)
	}
	return nil
}

func shownOrExcused(g *Graph, excused func(digest.Digest) bool) func(digest.Digest) bool {
	return func(d digest.Digest) bool { return g.Has(d) || excused != nil && excused(d) }
}

// AcceptStates records heads as the accepted heads of resource. Only revisions
// the caller trusts belong here: an accepted head is later allowed even if its
// author has been removed. Accepted heads a compaction removed (excused) are
// dropped. The check runs again under the lock, so a view that
// became stale while the caller was working is rejected rather than silently dropped.
func (c *Checkpoints) AcceptStates(resource string, g *Graph, excused func(digest.Digest) bool, heads []digest.Digest) error {
	heads = append([]digest.Digest(nil), heads...)
	sortDigests(heads)
	return c.update(func(f *checkpointFile) (bool, error) {
		if d, gone := missingFrom(f.States[resource], shownOrExcused(g, excused)); gone {
			return false, fmt.Errorf("%w: %s revision %s is missing from storage", ErrRollback, resource, d)
		}
		if sameDigests(f.States[resource], heads) {
			return false, nil
		}
		if f.States == nil {
			f.States = map[string][]digest.Digest{}
		}
		f.States[resource] = heads
		return true, nil
	})
}
