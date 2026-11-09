package wsp

import (
	"bytes"
	"context"
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/enbu-net/enbu/pkg/age"
	"github.com/enbu-net/enbu/pkg/clock"
	"github.com/enbu-net/enbu/pkg/signing"
	"github.com/enbu-net/enbu/pkg/storage"
	"github.com/opencontainers/go-digest"
)

// INPUT-1, INPUT-2 and GEN-7: decoding what storage or the disk holds never
// panics, accepts only canonical encodings, and whatever it accepts satisfies
// the protocol's invariants. The fuzzed body is signed with a real key where a
// signature is needed, so mutations reach the checks behind it.

func mustBody(t testing.TB, v any) []byte {
	t.Helper()
	b, err := encMode.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func sealed(t testing.TB, body []byte, signer signing.Signer, domain string, sign bool) []byte {
	t.Helper()
	if !sign {
		return body
	}
	sig, err := signer.Sign(domain, body)
	if err != nil {
		t.Fatal(err)
	}
	blob, err := Signed{Body: body, Signature: sig}.Encode()
	if err != nil {
		t.Fatal(err)
	}
	return blob
}

// canonicalBody checks that accepted bytes have exactly one encoding.
func canonicalBody(t *testing.T, blob []byte, v any) []byte {
	t.Helper()
	s, err := DecodeSigned(blob)
	if err != nil {
		t.Fatalf("accepted bytes are no envelope: %v", err)
	}
	again, err := encMode.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(again, s.Body) {
		t.Fatalf("accepted a non-canonical body:\n%x\nre-encodes to\n%x", s.Body, again)
	}
	return s.Body
}

func FuzzSignedEnvelope(f *testing.F) {
	f.Add(mustBody(f, Signed{Body: []byte("b"), Signature: []byte("s")}))
	f.Add([]byte{0xa2, 0x63, 'b', 'o', 'd'})
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		s, err := DecodeSigned(data)
		if err != nil {
			return
		}
		if len(data) > MaxSignedBytes || len(s.Body) == 0 || len(s.Signature) == 0 {
			t.Fatalf("accepted an envelope of %d bytes with body %d and signature %d bytes", len(data), len(s.Body), len(s.Signature))
		}
		again, err := s.Encode()
		if err != nil || !bytes.Equal(again, data) {
			t.Fatalf("accepted a non-canonical envelope %x (re-encodes to %x, %v)", data, again, err)
		}
	})
}

func FuzzStateCodec(f *testing.F) {
	fx := newStateFixture(f)
	base := fx.state(fx.bob)
	f.Add(mustBody(f, base), true)
	withParent := fx.state(fx.bob, digest.FromString("deleted parent"))
	f.Add(mustBody(f, withParent), true)
	// GEN-7: the largest Generation a member can sign behind a missing parent.
	top := withParent
	top.Generation = math.MaxUint64
	f.Add(mustBody(f, top), true)
	f.Add(mustBody(f, base), false)
	f.Fuzz(func(t *testing.T, body []byte, sign bool) {
		blob := sealed(t, body, fx.bob.signer, signing.DomainState, sign)
		st, err := VerifyRevision(fx.view, testWorkspace, testResource, digest.FromBytes(blob), blob)
		if err != nil {
			return
		}
		canonicalBody(t, blob, st.State)
		if err := st.validate(); err != nil {
			t.Fatalf("accepted an invalid State: %v", err)
		}
		if (st.Generation == 1) != (len(st.Parents) == 0) || len(st.Parents) > MaxParents || !slices.IsSorted(st.Parents) {
			t.Fatalf("accepted generation %d with parents %v", st.Generation, st.Parents)
		}
		c, ok := fx.view.Get(st.Control)
		if !ok {
			t.Fatal("accepted a State naming an unknown Control")
		}
		if _, ok := c.Principal(st.Author); !ok {
			t.Fatal("accepted a State whose author is not a principal of its Control")
		}
		// GEN-7: a revision on top of an accepted one must be writable.
		if next := NextGeneration([]*VerifiedState{st}); next <= st.Generation {
			t.Fatalf("generation %d accepted, but the next revision gets %d", st.Generation, next)
		}
	})
}

func FuzzControlCodec(f *testing.F) {
	store, alice, genesisDigest := workspace(f)
	genesis, err := LoadControl(context.Background(), store, testWorkspace, genesisDigest, nil)
	if err != nil {
		f.Fatal(err)
	}
	head, _ := genesis.Head()
	bob := newActor(f, false)
	child := Control{Workspace: testWorkspace, Parents: []digest.Digest{head.Digest}, Height: 1,
		Principals: []Principal{alice.p, bob.p}, Author: alice.p.ID}
	f.Add(mustBody(f, child.canonical()), true)
	f.Add(mustBody(f, head.Control), true)
	f.Add(mustBody(f, child.canonical()), false)
	f.Fuzz(func(t *testing.T, body []byte, sign bool) {
		blob := sealed(t, body, alice.signer, signing.DomainControl, sign)
		if v, err := VerifyGenesis(testWorkspace, blob, digest.FromBytes(blob)); err == nil {
			canonicalBody(t, blob, v.Control)
			if len(v.Parents) != 0 || v.Height != 0 {
				t.Fatalf("accepted a genesis with parents %v height %d", v.Parents, v.Height)
			}
			if a, ok := v.Principal(v.Author); !ok || !a.Admin {
				t.Fatal("accepted a genesis whose author is not its admin")
			}
			checkPrincipals(t, v.Control)
		}
		v, err := VerifyChild([]*Verified{head}, blob)
		if err != nil {
			return
		}
		canonicalBody(t, blob, v.Control)
		if v.Height != head.Height+1 || !slices.Equal(v.Parents, []digest.Digest{head.Digest}) {
			t.Fatalf("accepted a child with height %d and parents %v", v.Height, v.Parents)
		}
		if a, ok := head.Principal(v.Author); !ok || !a.Admin {
			t.Fatal("accepted a child whose author is not an admin of its parent")
		}
		checkPrincipals(t, v.Control)
	})
}

func checkPrincipals(t *testing.T, c Control) {
	t.Helper()
	admin := false
	for i, p := range c.Principals {
		if p.ID != p.Signing.DeviceID() {
			t.Fatalf("principal %s does not match its key", p.ID)
		}
		if _, err := age.ParseRecipient(p.Recipient); err != nil {
			t.Fatalf("principal %s has a recipient that is not post-quantum", p.ID)
		}
		if i > 0 && c.Principals[i-1].ID >= p.ID {
			t.Fatal("principals are not strictly sorted")
		}
		admin = admin || p.Admin
	}
	if !admin {
		t.Fatal("accepted a Control without an admin")
	}
}

func FuzzJoinRequestCodec(f *testing.F) {
	requester := newActor(f, false)
	valid, err := NewJoinRequest(testWorkspace, requester.p.Recipient, time.Unix(1700000000, 0), requester.signer)
	if err != nil {
		f.Fatal(err)
	}
	s, err := DecodeSigned(valid)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(s.Body, true)
	f.Add(valid, false)
	f.Fuzz(func(t *testing.T, body []byte, sign bool) {
		blob := sealed(t, body, requester.signer, signing.DomainJoin, sign)
		r, err := VerifyJoinRequest(testWorkspace, blob)
		if err != nil {
			return
		}
		signed := canonicalBody(t, blob, *r)
		if r.Workspace != testWorkspace {
			t.Fatalf("accepted a request for workspace %q", r.Workspace)
		}
		if err := r.DeviceID().Validate(); err != nil {
			t.Fatalf("accepted a request whose device ID is invalid: %v", err)
		}
		if _, err := age.ParseRecipient(r.Recipient); err != nil {
			t.Fatal("accepted a request with a recipient that is not post-quantum")
		}
		env, _ := DecodeSigned(blob)
		if err := signing.Verify(r.Signing, signing.DomainJoin, signed, env.Signature); err != nil {
			t.Fatal("accepted a request its own key did not sign")
		}
	})
}

// FuzzTrustFile: a trust.json that does not parse, or names an empty
// workspace or an invalid genesis, is refused; it is never read as "nothing
// pinned", which would let enbu.toml choose a new root.
func FuzzTrustFile(f *testing.F) {
	g := digest.FromString("genesis")
	f.Add([]byte(`{"workspaces":{"w":"` + string(g) + `"},"repositories":{"/r/enbu.toml":"w"}}`))
	f.Add([]byte(`{"workspaces":{"":"` + string(g) + `"}}`))
	f.Add([]byte(`{"workspaces":{"w":"sha256:00"}}`))
	f.Add([]byte(`null`))
	f.Add([]byte(`{`))
	f.Fuzz(func(t *testing.T, data []byte) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "trust.json"), data, 0o600); err != nil {
			t.Fatal(err)
		}
		tr := OpenTrust(dir, clock.New())
		pinned, err := tr.Pinned("w")
		if err != nil {
			return
		}
		var f trustFile
		if json.Unmarshal(data, &f) != nil {
			t.Fatalf("a trust file that does not parse was read as %v", pinned)
		}
		for ws, gen := range f.Workspaces {
			if ws == "" || validDigest(gen) != nil {
				t.Fatalf("a trust file with workspace %q and genesis %q was accepted", ws, gen)
			}
		}
		if want := f.root("w"); pinned != want {
			t.Fatalf("read %v, the file pins %v", pinned, want)
		}
		// A pinned root keeps stopping a different one.
		if pinned != (Root{}) {
			other := Root{Workspace: "w", Genesis: digest.FromString("another genesis")}
			if other != pinned && tr.Check(other, "", PinFirst) == nil {
				t.Fatal("a different genesis passed the pin")
			}
		}
	})
}

// FuzzCheckpointFile: a checkpoint that does not parse is refused, never read
// as "nothing accepted", which would hide a rollback.
func FuzzCheckpointFile(f *testing.F) {
	f.Add([]byte(`{"control":["` + string(digest.FromString("c")) + `"],"states":{"secrets/x":3}}`))
	f.Add([]byte(`{"states":{"secrets/x":-1}}`))
	f.Add([]byte(`[]`))
	f.Fuzz(func(t *testing.T, data []byte) {
		dir := t.TempDir()
		c := OpenCheckpoints(dir, testWorkspace, digest.FromString("g"), clock.New())
		if err := os.WriteFile(c.path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		gen, err := c.Generation("secrets/x")
		if err != nil {
			return
		}
		var cf checkpointFile
		if json.Unmarshal(data, &cf) != nil {
			t.Fatalf("a checkpoint that does not parse was read as generation %d", gen)
		}
		if gen != cf.States["secrets/x"] {
			t.Fatalf("read generation %d, the file holds %d", gen, cf.States["secrets/x"])
		}
		// Whatever was read is enforced: a view below it is a rollback.
		if gen > 0 {
			sv := &StateView{States: map[digest.Digest]*VerifiedState{"x": {State: State{Generation: gen - 1}}}}
			if c.CheckState("secrets/x", sv, nil) == nil {
				t.Fatalf("a view below the accepted generation %d passed", gen)
			}
		}
	})
}

// TestNextGenerationNeverWraps is GEN-7 (F3) end to end: a member signs the
// largest Generation behind a parent storage no longer shows; if the reader
// accepts it, a revision on top must still be writable.
func TestNextGenerationNeverWraps(t *testing.T) {
	fx := newStateFixture(t)
	st := fx.state(fx.bob, digest.FromString("deleted parent"))
	st.Generation = math.MaxUint64
	// Signed as an attacker would, without SignState's checks.
	blob := sealed(t, mustBody(t, st), fx.bob.signer, signing.DomainState, true)
	rev := digest.FromBytes(blob)
	if err := fx.store.Publish(context.Background(), storage.Object{Kind: storage.KindState, Scope: st.Scope(), Rev: rev, Head: blob, Payload: []byte("c")}); err != nil {
		t.Fatal(err)
	}
	sv, err := LoadStates(context.Background(), fx.store, fx.view, testWorkspace, testResource)
	if err != nil {
		t.Fatal(err)
	}
	accepted, ok := sv.States[rev]
	if !ok {
		return // refused: nothing to write on top of
	}
	next := NextGeneration([]*VerifiedState{accepted})
	if next <= accepted.Generation {
		t.Fatalf("accepted generation %d; the next revision gets %d and can never be written", accepted.Generation, next)
	}
	child := fx.state(fx.alice, rev)
	child.Generation = next
	if _, err := SignState(child, fx.alice.signer); err != nil {
		t.Fatalf("the revision on top cannot be signed: %v", err)
	}
}
