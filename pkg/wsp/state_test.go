package wsp

import (
	"errors"
	"testing"

	"github.com/opencontainers/go-digest"
)

type stateFixture struct {
	ctrl  *Verified
	alice actor
	bob   actor
}

func newStateFixture(t *testing.T) stateFixture {
	t.Helper()
	alice, bob := newActor(t, true), newActor(t, false)
	c := Control{Workspace: testWorkspace, Principals: []Principal{alice.p, bob.p}, Author: alice.p.ID}.canonical()
	return stateFixture{ctrl: &Verified{Control: c, Digest: digest.FromString("control")}, alice: alice, bob: bob}
}

func (f stateFixture) state(author actor) State {
	return State{Workspace: testWorkspace, Resource: "secrets/prod", Sequence: 1, ControlGeneration: f.ctrl.Generation,
		Control: f.ctrl.Digest, Ciphertext: digest.FromString("ciphertext"), Author: author.p.ID}
}

func TestStateRoundTrip(t *testing.T) {
	f := newStateFixture(t)
	blob, err := SignState(f.state(f.bob), f.bob.signer)
	if err != nil {
		t.Fatal(err)
	}
	st, err := VerifyState(f.ctrl, testWorkspace, "secrets/prod", blob)
	if err != nil {
		t.Fatal(err)
	}
	if st.Author != f.bob.p.ID || st.Digest != digest.FromBytes(blob) {
		t.Fatalf("unexpected state: %+v", st)
	}
}

func TestFakeSecretRejected(t *testing.T) {
	f := newStateFixture(t)
	attacker := newActor(t, false)
	// A state signed by a key the Control does not list.
	blob, err := SignState(f.state(attacker), attacker.signer)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyState(f.ctrl, testWorkspace, "secrets/prod", blob); !errors.Is(err, ErrInvalid) {
		t.Fatalf("outsider state accepted: %v", err)
	}
	// An attacker claiming a member's id with a signature of their own.
	forged := f.state(f.bob)
	body, _ := encMode.Marshal(forged)
	sig, _ := attacker.signer.Sign("enbu.workspace-state.v1", body)
	blob, _ = Signed{Body: body, Signature: sig}.Encode()
	if _, err := VerifyState(f.ctrl, testWorkspace, "secrets/prod", blob); !errors.Is(err, ErrInvalid) {
		t.Fatalf("forged author accepted: %v", err)
	}
}

func TestStateTampering(t *testing.T) {
	f := newStateFixture(t)
	good, err := SignState(f.state(f.bob), f.bob.signer)
	if err != nil {
		t.Fatal(err)
	}
	signed, _ := DecodeSigned(good)
	for name, mutate := range map[string]func(*State){
		"ciphertext digest": func(s *State) { s.Ciphertext = digest.FromString("evil") },
		"author":            func(s *State) { s.Author = f.alice.p.ID },
		"workspace":         func(s *State) { s.Workspace = "0192f3a0-7c1e-7a55-9d3c-000000000000" },
		"resource":          func(s *State) { s.Resource = "secrets/dev" },
		"sequence":          func(s *State) { s.Sequence, s.Previous = 2, digest.FromString("p") },
	} {
		t.Run(name, func(t *testing.T) {
			s := f.state(f.bob)
			mutate(&s)
			body, _ := encMode.Marshal(s)
			blob, _ := Signed{Body: body, Signature: signed.Signature}.Encode()
			resource, workspace := "secrets/prod", testWorkspace
			if s.Resource != "secrets/prod" {
				resource = s.Resource // let the reader ask for what the attacker claims
			}
			if s.Workspace != testWorkspace {
				workspace = s.Workspace
			}
			if _, err := VerifyState(f.ctrl, workspace, resource, blob); !errors.Is(err, ErrInvalid) {
				t.Fatalf("tampered state accepted: %v", err)
			}
		})
	}
}

func TestStateForOtherResourceRejected(t *testing.T) {
	f := newStateFixture(t)
	blob, _ := SignState(f.state(f.bob), f.bob.signer)
	if _, err := VerifyState(f.ctrl, testWorkspace, "secrets/dev", blob); !errors.Is(err, ErrInvalid) {
		t.Fatalf("state replayed under another resource: %v", err)
	}
}

func TestRemovedMemberStateRejected(t *testing.T) {
	f := newStateFixture(t)
	blob, _ := SignState(f.state(f.bob), f.bob.signer)
	after := &Verified{Control: Control{Workspace: testWorkspace, Generation: 1, Principals: []Principal{f.alice.p}, Author: f.alice.p.ID}, Digest: digest.FromString("control2")}
	if _, err := VerifyState(after, testWorkspace, "secrets/prod", blob); !errors.Is(err, ErrInvalid) {
		t.Fatalf("removed member's state accepted: %v", err)
	}
}

func TestStateSignedUnderNewerControlIsRollback(t *testing.T) {
	f := newStateFixture(t)
	s := f.state(f.alice)
	s.ControlGeneration, s.Control = 5, digest.FromString("newer")
	blob, _ := SignState(s, f.alice.signer)
	if _, err := VerifyState(f.ctrl, testWorkspace, "secrets/prod", blob); !errors.Is(err, ErrRollback) {
		t.Fatalf("state from the future accepted: %v", err)
	}
	s.ControlGeneration, s.Control = f.ctrl.Generation, digest.FromString("other")
	blob, _ = SignState(s, f.alice.signer)
	if _, err := VerifyState(f.ctrl, testWorkspace, "secrets/prod", blob); !errors.Is(err, ErrInvalid) {
		t.Fatalf("state naming a foreign control accepted: %v", err)
	}
}

func TestStateSignerMustBeAuthor(t *testing.T) {
	f := newStateFixture(t)
	if _, err := SignState(f.state(f.bob), f.alice.signer); !errors.Is(err, ErrInvalid) {
		t.Fatalf("signer other than author: %v", err)
	}
}

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
	// A different, validly signed state at the same sequence is a lost update
	// between concurrent writers, not a rollback.
	if err := cps.AcceptState(mk(2, "other")); err != nil {
		t.Fatalf("concurrent writer's state at the same sequence rejected: %v", err)
	}
	if err := cps.CheckState(s1); !errors.Is(err, ErrRollback) {
		t.Fatalf("older state accepted after recording a sibling: %v", err)
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
