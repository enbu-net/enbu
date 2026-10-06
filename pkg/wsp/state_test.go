package wsp

import (
	"errors"
	"testing"

	"github.com/enbu-net/enbu/pkg/signing"
	digest "github.com/opencontainers/go-digest"
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
	sig, _ := attacker.signer.Sign(signing.DomainState, body)
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

// signedBody signs an arbitrary State body, bypassing SignState's own checks,
// so VerifyState's validation is exercised on what a hostile writer could send.
func signedBody(t *testing.T, s State, by actor) []byte {
	t.Helper()
	body, err := encMode.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := by.signer.Sign(signing.DomainState, body)
	if err != nil {
		t.Fatal(err)
	}
	blob, err := Signed{Body: body, Signature: sig}.Encode()
	if err != nil {
		t.Fatal(err)
	}
	return blob
}

func TestStateSequenceAndPreviousMustAgree(t *testing.T) {
	f := newStateFixture(t)
	first := f.state(f.bob)
	first.Previous = digest.FromString("previous")
	later := f.state(f.bob)
	later.Sequence = 2
	for name, s := range map[string]State{"first state with a previous": first, "later state without one": later, "sequence zero": func() State { z := f.state(f.bob); z.Sequence = 0; return z }()} {
		t.Run(name, func(t *testing.T) {
			if _, err := SignState(s, f.bob.signer); !errors.Is(err, ErrInvalid) {
				t.Fatalf("SignState accepted it: %v", err)
			}
			// Validly signed by a member, but malformed: the reader must refuse it too.
			if _, err := VerifyState(f.ctrl, testWorkspace, "secrets/prod", signedBody(t, s, f.bob)); !errors.Is(err, ErrInvalid) {
				t.Fatalf("VerifyState accepted it: %v", err)
			}
		})
	}
}

// A state signed under an earlier generation is normal: its author may simply
// not have seen the newer Control yet. Only a state from the future is suspect.
func TestStateFromAnEarlierControlGenerationIsAccepted(t *testing.T) {
	f := newStateFixture(t)
	head := &Verified{Control: f.ctrl.Control, Digest: digest.FromString("control 3")}
	head.Generation = 3
	s := f.state(f.bob)
	s.ControlGeneration, s.Control = 1, digest.FromString("control 1")
	blob, err := SignState(s, f.bob.signer)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyState(head, testWorkspace, "secrets/prod", blob); err != nil {
		t.Fatalf("a state from an earlier generation was rejected: %v", err)
	}
}

func TestHistoricalStateIsJudgedByTheControlItWasWrittenUnder(t *testing.T) {
	f := newStateFixture(t)
	blob, err := SignState(f.state(f.bob), f.bob.signer)
	if err != nil {
		t.Fatal(err)
	}
	gen, ctl, err := StateControl(blob)
	if err != nil || gen != f.ctrl.Generation || ctl != f.ctrl.Digest {
		t.Fatalf("StateControl = %d %s %v", gen, ctl, err)
	}
	// Bob is removed in the next generation.
	after := &Verified{Control: Control{Workspace: testWorkspace, Generation: 1, Principals: []Principal{f.alice.p}, Author: f.alice.p.ID}, Digest: digest.FromString("after removal")}
	if _, err := VerifyState(after, testWorkspace, "secrets/prod", blob); !errors.Is(err, ErrInvalid) {
		t.Fatalf("a removed member's state is not current: %v", err)
	}
	// But it was validly written, and is accepted against the control it names.
	st, err := VerifyHistoricalState(f.ctrl, testWorkspace, "secrets/prod", blob)
	if err != nil || st.Author != f.bob.p.ID {
		t.Fatalf("historical verification: %v", err)
	}
}

func TestHistoricalStateStillNeedsAMemberAndASignature(t *testing.T) {
	f := newStateFixture(t)
	outsider := newActor(t, false)
	forged, err := SignState(f.state(outsider), outsider.signer)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyHistoricalState(f.ctrl, testWorkspace, "secrets/prod", forged); !errors.Is(err, ErrInvalid) {
		t.Fatalf("a state by someone who was never a member: %v", err)
	}
	good, _ := SignState(f.state(f.bob), f.bob.signer)
	signed, _ := DecodeSigned(good)
	signed.Signature[0] ^= 1
	tampered, _ := signed.Encode()
	if _, err := VerifyHistoricalState(f.ctrl, testWorkspace, "secrets/prod", tampered); !errors.Is(err, ErrInvalid) {
		t.Fatalf("a bad signature: %v", err)
	}
	// Judged by a different generation than the one it names.
	other := &Verified{Control: f.ctrl.Control, Digest: digest.FromString("another control")}
	if _, err := VerifyHistoricalState(other, testWorkspace, "secrets/prod", good); !errors.Is(err, ErrInvalid) {
		t.Fatalf("a state judged by a control it does not name: %v", err)
	}
	if _, err := VerifyHistoricalState(f.ctrl, testWorkspace, "secrets/dev", good); !errors.Is(err, ErrInvalid) {
		t.Fatalf("a state for another resource: %v", err)
	}
}
