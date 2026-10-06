package wsp

import (
	"errors"
	"os"
	"strings"
	"sync"
	"testing"

	digest "github.com/opencontainers/go-digest"
)

func TestCheckpointRollbackDetection(t *testing.T) {
	f := newStateFixture(t)
	cps := OpenCheckpoints(t.TempDir(), testWorkspace, digest.FromString("genesis"))
	mk := func(seq uint64, ct string) *VerifiedState {
		s := f.state(f.bob)
		s.Sequence = seq
		if seq > 1 {
			s.Previous = digest.FromString("prev")
		}
		s.Ciphertext = digest.FromString(ct)
		blob, err := SignState(s, f.bob.signer)
		if err != nil {
			t.Fatal(err)
		}
		v, err := VerifyState(f.ctrl, testWorkspace, "secrets/prod", blob)
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	s1, s2 := mk(1, "a"), mk(2, "b")
	if err := cps.AcceptState(s1); err != nil {
		t.Fatal(err)
	}
	if err := cps.AcceptState(s2); err != nil {
		t.Fatal(err)
	}
	if err := cps.AcceptState(s2); err != nil {
		t.Fatalf("re-accepting the same state: %v", err)
	}
	if err := cps.CheckState(s1); !errors.Is(err, ErrRollback) {
		t.Fatalf("older state accepted: %v", err)
	}
	// A different, validly signed state at the same sequence is a fork: it is
	// reported and stops the read, and it does not replace what was accepted.
	sibling := mk(2, "other")
	if err := cps.CheckState(sibling); !errors.Is(err, ErrRollback) || !strings.Contains(err.Error(), "fork") {
		t.Fatalf("a forked state at the same sequence was not rejected: %v", err)
	}
	if err := cps.AcceptState(sibling); !errors.Is(err, ErrRollback) {
		t.Fatalf("a forked state was accepted: %v", err)
	}
	if cp, _ := cps.State("secrets/prod"); cp == nil || cp.Digest != s2.Digest {
		t.Fatalf("the accepted state was replaced: %+v", cp)
	}
	if err := cps.CheckState(s1); !errors.Is(err, ErrRollback) {
		t.Fatalf("older state accepted: %v", err)
	}
	// The checkpoint survives reopening: it is stored locally.
	reopened := &Checkpoints{path: cps.path}
	if err := reopened.CheckState(s1); !errors.Is(err, ErrRollback) {
		t.Fatalf("checkpoint was not persisted: %v", err)
	}
}

func TestControlCheckpointIsMonotonic(t *testing.T) {
	cps := OpenCheckpoints(t.TempDir(), testWorkspace, digest.FromString("genesis"))
	g1 := &Verified{Control: Control{Generation: 1}, Digest: digest.FromString("1")}
	g2 := &Verified{Control: Control{Generation: 2}, Digest: digest.FromString("2")}
	if err := cps.AcceptControl(g2); err != nil {
		t.Fatal(err)
	}
	if err := cps.AcceptControl(g1); !errors.Is(err, ErrRollback) {
		t.Fatalf("older control accepted: %v", err)
	}
	fork := &Verified{Control: Control{Generation: 2}, Digest: digest.FromString("fork")}
	if err := cps.AcceptControl(fork); !errors.Is(err, ErrRollback) {
		t.Fatalf("forked control accepted: %v", err)
	}
	if err := cps.AcceptControl(g2); err != nil {
		t.Fatalf("same control again: %v", err)
	}
	if cp, _ := cps.Control(); cp == nil || cp.Generation != 2 {
		t.Fatalf("checkpoint: %+v", cp)
	}
}

func TestCorruptCheckpointFails(t *testing.T) {
	cps := OpenCheckpoints(t.TempDir(), testWorkspace, digest.FromString("genesis"))
	if err := cps.AcceptControl(&Verified{Control: Control{Generation: 1}, Digest: digest.FromString("1")}); err != nil {
		t.Fatal(err)
	}
	if err := writeFile(cps.path, "{not json"); err != nil {
		t.Fatal(err)
	}
	if _, err := cps.Control(); err == nil {
		t.Fatal("corrupt checkpoint read as empty")
	}
}

func writeFile(path, s string) error { return os.WriteFile(path, []byte(s), 0o600) }

func TestCheckpointsAreSeparatePerWorkspaceAndGenesis(t *testing.T) {
	dir := t.TempDir()
	genesisA, genesisB := digest.FromString("a"), digest.FromString("b")
	a := OpenCheckpoints(dir, testWorkspace, genesisA)
	if err := a.AcceptControl(&Verified{Control: Control{Generation: 4}, Digest: digest.FromString("4")}); err != nil {
		t.Fatal(err)
	}
	// Another trust root, or another workspace, starts its own history; its
	// generation 0 is not a rollback of the other's generation 4.
	for name, other := range map[string]*Checkpoints{
		"other genesis":   OpenCheckpoints(dir, testWorkspace, genesisB),
		"other workspace": OpenCheckpoints(dir, "0192f3a0-7c1e-7a55-9d3c-000000000000", genesisA),
	} {
		if cp, err := other.Control(); err != nil || cp != nil {
			t.Fatalf("%s sees %+v %v", name, cp, err)
		}
		if err := other.AcceptControl(&Verified{Control: Control{Generation: 0}, Digest: digest.FromString("0")}); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}
	if cp, _ := a.Control(); cp == nil || cp.Generation != 4 {
		t.Fatalf("the first history changed: %+v", cp)
	}
}

func TestUnsupportedCheckpointVersionFails(t *testing.T) {
	cps := OpenCheckpoints(t.TempDir(), testWorkspace, digest.FromString("g"))
	if err := writeFile(cps.path, `{"version": 2}`); err != nil {
		t.Fatal(err)
	}
	if _, err := cps.Control(); err == nil {
		t.Fatal("an unknown checkpoint version was read as empty")
	}
	if err := cps.AcceptControl(&Verified{Control: Control{Generation: 1}, Digest: digest.FromString("1")}); err == nil {
		t.Fatal("an unknown checkpoint version was overwritten")
	}
}

func TestAcceptStateRejectsWhatBecameStaleMeanwhile(t *testing.T) {
	f := newStateFixture(t)
	cps := OpenCheckpoints(t.TempDir(), testWorkspace, digest.FromString("g"))
	mk := func(seq uint64) *VerifiedState {
		s := f.state(f.bob)
		s.Sequence = seq
		if seq > 1 {
			s.Previous = digest.FromString("prev")
		}
		blob, err := SignState(s, f.bob.signer)
		if err != nil {
			t.Fatal(err)
		}
		v, err := VerifyState(f.ctrl, testWorkspace, "secrets/prod", blob)
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	old, newer := mk(2), mk(3)
	if err := cps.CheckState(old); err != nil { // nothing is recorded yet
		t.Fatal(err)
	}
	// Another process accepts a newer state between the caller's check and its accept.
	if err := cps.AcceptState(newer); err != nil {
		t.Fatal(err)
	}
	if err := cps.AcceptState(old); !errors.Is(err, ErrRollback) {
		t.Fatalf("a stale state was silently accepted: %v", err)
	}
	if cp, _ := cps.State("secrets/prod"); cp == nil || cp.Sequence != 3 {
		t.Fatalf("checkpoint moved: %+v", cp)
	}
}

// Many processes (here, many Checkpoints on one file) accept states at once;
// the file must end at the highest sequence, never a lower one.
func TestConcurrentAcceptsNeverMoveACheckpointBack(t *testing.T) {
	f := newStateFixture(t)
	path := OpenCheckpoints(t.TempDir(), testWorkspace, digest.FromString("g")).path
	var wg sync.WaitGroup
	for seq := uint64(1); seq <= 24; seq++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s := f.state(f.bob)
			s.Sequence = seq
			if seq > 1 {
				s.Previous = digest.FromString("prev")
			}
			blob, err := SignState(s, f.bob.signer)
			if err != nil {
				t.Error(err)
				return
			}
			v, err := VerifyState(f.ctrl, testWorkspace, "secrets/prod", blob)
			if err != nil {
				t.Error(err)
				return
			}
			c := &Checkpoints{path: path}
			if err := c.AcceptState(v); err != nil && !errors.Is(err, ErrRollback) {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	cp, err := (&Checkpoints{path: path}).State("secrets/prod")
	if err != nil || cp == nil || cp.Sequence != 24 {
		t.Fatalf("final checkpoint %+v %v, want sequence 24", cp, err)
	}
}
