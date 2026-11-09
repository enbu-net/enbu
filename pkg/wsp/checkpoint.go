package wsp

import (
	"context"
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

	"github.com/enbu-net/enbu/pkg/clock"
	"github.com/enbu-net/enbu/pkg/fsutil"

	"github.com/opencontainers/go-digest"
)

// checkpointVersion is the on-disk format. Version 3 kept accepted heads per
// resource instead of a Generation: its Control heads carry over and its
// resources start empty, like a file of an older format.
const checkpointVersion = 4

type checkpointFile struct {
	Version int               `json:"version"`
	Control []digest.Digest   `json:"control,omitempty"`
	States  map[string]uint64 `json:"states,omitempty"` // accepted Generation per resource
}

// Checkpoints persists what a client has accepted, locally only, so storage
// cannot later show less than it already showed. It needs no server.
//
// For the Control DAG, which is never deleted, it keeps the accepted heads: a
// later view must still contain each of them. For a resource, whose old
// revisions may be deleted, it keeps the highest Generation accepted: a later
// view must show a verified revision of at least that Generation. Storage
// hiding an accepted head behind a sibling branch of equal or higher
// Generation is not detected; that branch still needs a member's signature.
//
// Every update is a read-modify-write under an OS file lock, so concurrent
// processes cannot overwrite each other.
type Checkpoints struct {
	path  string
	clock clock.Clock
	mu    sync.Mutex
}

// OpenCheckpoints returns the checkpoint file for a workspace under dir. A
// checkpoint belongs to one trust root, so the genesis digest is part of the
// name: pointing the same workspace at a different genesis starts a separate
// history instead of being mistaken for a rollback. Both values are hashed so
// they cannot escape dir.
func OpenCheckpoints(dir, workspace string, genesis digest.Digest, c clock.Clock) *Checkpoints {
	sum := sha256.Sum256([]byte(workspace + "\x00" + string(genesis)))
	return &Checkpoints{clock: c, path: filepath.Join(dir, hex.EncodeToString(sum[:])+".json")}
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
		Version int             `json:"version"`
		Control []digest.Digest `json:"control"`
	}
	if err := json.Unmarshal(b, &v); err != nil || v.Version < 1 || v.Version > checkpointVersion {
		return checkpointFile{}, fmt.Errorf("corrupt checkpoint file %s", c.path)
	}
	switch {
	case v.Version == 3:
		return checkpointFile{Version: checkpointVersion, Control: v.Control}, nil
	case v.Version < checkpointVersion:
		return checkpointFile{Version: checkpointVersion}, nil
	}
	var f checkpointFile
	if err := json.Unmarshal(b, &f); err != nil {
		return checkpointFile{}, fmt.Errorf("corrupt checkpoint file %s", c.path)
	}
	return f, nil
}

func (c *Checkpoints) write(f checkpointFile) error {
	f.Version = checkpointVersion
	b, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(c.path, b)
}

const lockTimeout = 5 * time.Second

// lockFile takes an exclusive OS lock on path+".lock", waiting up to
// lockTimeout, and returns the function that releases it.
func lockFile(path string, c clock.Clock) (func(), error) {
	if c == nil {
		c = clock.New()
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	lock, err := os.OpenFile(path+".lock", os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	ctx, cancel := clock.WithTimeout(context.Background(), c, lockTimeout)
	defer cancel()
	for {
		ok, err := tryLock(lock)
		if err != nil {
			_ = lock.Close()
			return nil, err
		}
		if ok {
			return func() { unlock(lock); _ = lock.Close() }, nil
		}
		if err := clock.Wait(ctx, c, 10*time.Millisecond); err != nil {
			_ = lock.Close()
			return nil, fmt.Errorf("timed out waiting for the lock %s.lock", path)
		}
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
	return fsutil.Rename(tmp.Name(), path)
}

// update runs fn on the current contents while holding the file lock, and
// writes the result back if fn reports a change.
func (c *Checkpoints) update(fn func(*checkpointFile) (bool, error)) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	release, err := lockFile(c.path, c.clock)
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

// Generation returns the accepted Generation of resource, or 0 if none.
func (c *Checkpoints) Generation(resource string) (uint64, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	f, err := c.read()
	return f.States[resource], err
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
		for _, d := range f.Control {
			if _, ok := view.Get(d); !ok {
				return false, fmt.Errorf("%w: accepted control %s is missing from storage", ErrRollback, d)
			}
		}
		if sameDigests(f.Control, heads) {
			return false, nil
		}
		f.Control = heads
		return true, nil
	})
}

// CheckState rejects a view of resource whose verified revisions are all of a
// lower Generation than this client accepted. sv may be nil for a resource
// storage shows nothing of. It does not record anything.
func (c *Checkpoints) CheckState(resource string, sv *StateView) error {
	accepted, err := c.Generation(resource)
	if err != nil {
		return err
	}
	return rollbackBelow(resource, sv, accepted)
}

func rollbackBelow(resource string, sv *StateView, accepted uint64) error {
	if shown := sv.MaxGeneration(); shown < accepted {
		return fmt.Errorf("%w: storage shows %s up to generation %d, below the accepted %d", ErrRollback, resource, shown, accepted)
	}
	return nil
}

// AcceptState raises the accepted Generation of resource to generation, the
// highest Generation of the heads the caller read from sv. The check runs again
// under the lock, so a view that became stale while the caller was working is
// rejected rather than silently accepted.
func (c *Checkpoints) AcceptState(resource string, sv *StateView, generation uint64) error {
	return c.update(func(f *checkpointFile) (bool, error) {
		accepted := f.States[resource]
		if err := rollbackBelow(resource, sv, accepted); err != nil {
			return false, err
		}
		if generation <= accepted {
			return false, nil
		}
		if f.States == nil {
			f.States = map[string]uint64{}
		}
		f.States[resource] = generation
		return true, nil
	})
}
