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
// Updates are monotonic: they re-read the file and never move a value back, so
// two concurrent processes can at worst leave a checkpoint a step behind.
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
	c.mu.Lock()
	defer c.mu.Unlock()
	f, err := c.read()
	if err != nil {
		return err
	}
	if cp := f.Control; cp != nil {
		if v.Generation < cp.Generation || v.Generation == cp.Generation && v.Digest != cp.Digest {
			return fmt.Errorf("%w: control generation %d does not follow accepted generation %d", ErrRollback, v.Generation, cp.Generation)
		}
		if v.Generation == cp.Generation {
			return nil
		}
	}
	f.Control = &Checkpoint{Generation: v.Generation, Digest: v.Digest}
	return c.write(f)
}

// CheckState rejects st when its sequence is older than the accepted State of
// its resource. It does not record anything.
//
// A different State at the same sequence is accepted: both are validly signed,
// and backends whose ref update is best effort (OCI) can lose one of two
// concurrent writes, which looks exactly like that. Control is stricter because
// a diverging Control is a diverging authority.
func (c *Checkpoints) CheckState(st *VerifiedState) error {
	cp, err := c.State(st.Resource)
	if err != nil || cp == nil {
		return err
	}
	if st.Sequence < cp.Sequence {
		return fmt.Errorf("%w: %s sequence %d is older than accepted sequence %d", ErrRollback, st.Resource, st.Sequence, cp.Sequence)
	}
	return nil
}

// AcceptState checks st and then records it as the newest accepted State.
func (c *Checkpoints) AcceptState(st *VerifiedState) error {
	if err := c.CheckState(st); err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	f, err := c.read()
	if err != nil {
		return err
	}
	if cur, ok := f.States[st.Resource]; ok && (cur.Sequence > st.Sequence || cur.Sequence == st.Sequence && cur.Digest == st.Digest) {
		return nil // another process already recorded this or newer
	}
	if f.States == nil {
		f.States = map[string]StateCheckpoint{}
	}
	f.States[st.Resource] = StateCheckpoint{Sequence: st.Sequence, Digest: st.Digest}
	return c.write(f)
}
