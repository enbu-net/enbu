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

// StateCheckpoint is the newest State of one resource this client accepted.
type StateCheckpoint struct {
	Sequence uint64        `json:"sequence"`
	Digest   digest.Digest `json:"digest"`
}

type checkpointFile struct {
	Version int                        `json:"version"`
	Control *Checkpoint                `json:"control,omitempty"`
	States  map[string]StateCheckpoint `json:"states,omitempty"`
}

// Checkpoints persists what a client has accepted, locally only, so storage
// cannot later hand back something older. It needs no server.
//
// Every update is a read-modify-write under an OS file lock, so concurrent
// processes cannot overwrite each other, and an update never moves a value back.
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
		return checkpointFile{Version: 1}, nil
	}
	if err != nil {
		return checkpointFile{}, err
	}
	var f checkpointFile
	if err := json.Unmarshal(b, &f); err != nil || f.Version != 1 {
		return checkpointFile{}, fmt.Errorf("corrupt checkpoint file %s", c.path)
	}
	return f, nil
}

func (c *Checkpoints) write(f checkpointFile) error {
	if err := os.MkdirAll(filepath.Dir(c.path), 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(c.path), ".checkpoint-*")
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
	return os.Rename(tmp.Name(), c.path)
}

const lockTimeout = 5 * time.Second

// update runs fn on the current contents while holding the file lock, and
// writes the result back if fn reports a change.
func (c *Checkpoints) update(fn func(*checkpointFile) (bool, error)) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := os.MkdirAll(filepath.Dir(c.path), 0o700); err != nil {
		return err
	}
	lock, err := os.OpenFile(c.path+".lock", os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return err
	}
	defer func() { _ = lock.Close() }()
	deadline := time.Now().Add(lockTimeout)
	for {
		ok, err := tryLock(lock)
		if err != nil {
			return err
		}
		if ok {
			break
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("timed out waiting for the checkpoint lock %s.lock", c.path)
		}
		time.Sleep(10 * time.Millisecond)
	}
	defer unlock(lock)
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

// Control returns the accepted Control checkpoint, or nil if none.
func (c *Checkpoints) Control() (*Checkpoint, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	f, err := c.read()
	return f.Control, err
}

// State returns the accepted checkpoint for resource, or nil if none.
func (c *Checkpoints) State(resource string) (*StateCheckpoint, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	f, err := c.read()
	if err != nil {
		return nil, err
	}
	if s, ok := f.States[resource]; ok {
		return &s, nil
	}
	return nil, nil
}

// AcceptControl records v as the newest accepted Control. A generation below
// the checkpoint, or a different digest at the same generation, is rejected.
func (c *Checkpoints) AcceptControl(v *Verified) error {
	return c.update(func(f *checkpointFile) (bool, error) {
		if cp := f.Control; cp != nil {
			if v.Generation < cp.Generation || v.Generation == cp.Generation && v.Digest != cp.Digest {
				return false, fmt.Errorf("%w: control generation %d does not follow accepted generation %d", ErrRollback, v.Generation, cp.Generation)
			}
			if v.Generation == cp.Generation {
				return false, nil
			}
		}
		f.Control = &Checkpoint{Generation: v.Generation, Digest: v.Digest}
		return true, nil
	})
}

// CheckState rejects st when it is older than the accepted State of its
// resource, or a different State at the same sequence. The first is a rollback;
// the second is a fork: two states both claiming to be the next one after the
// same predecessor. Neither is resolved here. Detecting it and stopping is
// enough, and the user can sync again once storage settles.
// It does not record anything.
func (c *Checkpoints) CheckState(st *VerifiedState) error {
	cp, err := c.State(st.Resource)
	if err != nil || cp == nil {
		return err
	}
	return checkAgainst(st, *cp)
}

func checkAgainst(st *VerifiedState, cp StateCheckpoint) error {
	switch {
	case st.Sequence < cp.Sequence:
		return fmt.Errorf("%w: %s sequence %d is older than accepted sequence %d", ErrRollback, st.Resource, st.Sequence, cp.Sequence)
	case st.Sequence == cp.Sequence && st.Digest != cp.Digest:
		return fmt.Errorf("%w: %s has two different states at sequence %d (fork)", ErrRollback, st.Resource, st.Sequence)
	}
	return nil
}

// AcceptState records st as the newest accepted State of its resource. The
// check runs again under the lock, so a State that became stale or forked while
// the caller was working is rejected rather than silently dropped.
func (c *Checkpoints) AcceptState(st *VerifiedState) error {
	return c.update(func(f *checkpointFile) (bool, error) {
		cur, ok := f.States[st.Resource]
		if ok {
			if err := checkAgainst(st, cur); err != nil {
				return false, err
			}
			if cur.Sequence == st.Sequence {
				return false, nil // the very same state again
			}
		}
		if f.States == nil {
			f.States = map[string]StateCheckpoint{}
		}
		f.States[st.Resource] = StateCheckpoint{Sequence: st.Sequence, Digest: st.Digest}
		return true, nil
	})
}
