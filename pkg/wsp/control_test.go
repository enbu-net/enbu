package wsp

import (
	"errors"
	"strings"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/opencontainers/go-digest"
)

// genesisOf signs a one-admin genesis Control and returns its stored bytes and digest.
func genesisOf(t *testing.T, founder actor) ([]byte, digest.Digest) {
	t.Helper()
	blob, err := SignControl(Control{Workspace: testWorkspace, Principals: []Principal{founder.p}, Author: founder.p.ID}, founder.signer)
	if err != nil {
		t.Fatal(err)
	}
	return blob, digest.FromBytes(blob)
}

// nextOf signs the successor of prev with the given principals.
func nextOf(t *testing.T, prev *Verified, by actor, principals ...Principal) []byte {
	t.Helper()
	blob, err := SignControl(Control{Workspace: testWorkspace, Parents: []digest.Digest{prev.Digest}, Height: prev.Height + 1,
		Principals: principals, Author: by.p.ID}, by.signer)
	if err != nil {
		t.Fatal(err)
	}
	return blob
}

func TestControlGrowsOnlyThroughSignedSuccessors(t *testing.T) {
	alice, bob := newActor(t, true), newActor(t, false)
	blob, d := genesisOf(t, alice)
	genesis, err := VerifyGenesis(testWorkspace, blob, d)
	if err != nil {
		t.Fatal(err)
	}
	next, err := VerifyChild([]*Verified{genesis}, nextOf(t, genesis, alice, alice.p, bob.p))
	if err != nil {
		t.Fatal(err)
	}
	if next.Height != 1 || len(next.Recipients()) != 2 {
		t.Fatalf("unexpected control: %+v", next.Control)
	}
	if _, ok := next.Principal(bob.p.ID); !ok {
		t.Fatal("bob is not a principal")
	}
}

func TestOutsiderCannotSignControl(t *testing.T) {
	alice, mallory := newActor(t, true), newActor(t, true)
	blob, d := genesisOf(t, alice)
	genesis, _ := VerifyGenesis(testWorkspace, blob, d)
	forged := nextOf(t, genesis, mallory, alice.p, mallory.p)
	if _, err := VerifyChild([]*Verified{genesis}, forged); !errors.Is(err, ErrInvalid) {
		t.Fatalf("control signed by an outsider was accepted: %v", err)
	}
}

func TestMemberCannotSignControl(t *testing.T) {
	alice, bob := newActor(t, true), newActor(t, false)
	blob, d := genesisOf(t, alice)
	genesis, _ := VerifyGenesis(testWorkspace, blob, d)
	g1, err := VerifyChild([]*Verified{genesis}, nextOf(t, genesis, alice, alice.p, bob.p))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyChild([]*Verified{g1}, nextOf(t, g1, bob, alice.p, bob.p)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("member-signed control accepted: %v", err)
	}
}

func TestControlTampering(t *testing.T) {
	alice, bob, mallory := newActor(t, true), newActor(t, false), newActor(t, false)
	blob, d := genesisOf(t, alice)
	genesis, _ := VerifyGenesis(testWorkspace, blob, d)
	signed, err := DecodeSigned(nextOf(t, genesis, alice, alice.p, bob.p))
	if err != nil {
		t.Fatal(err)
	}
	// bobAt edits bob's entry wherever sorting placed it.
	bobAt := func(c *Control, f func(*Principal)) {
		for i := range c.Principals {
			if c.Principals[i].ID == bob.p.ID {
				f(&c.Principals[i])
			}
		}
	}
	for name, mutate := range map[string]func(*Control){
		"swap recipient":   func(c *Control) { bobAt(c, func(p *Principal) { p.Recipient = mallory.p.Recipient }) },
		"swap signing key": func(c *Control) { bobAt(c, func(p *Principal) { p.Signing = mallory.p.Signing }) },
		"add principal":    func(c *Control) { c.Principals = append(c.Principals, mallory.p) },
		"promote":          func(c *Control) { bobAt(c, func(p *Principal) { p.Admin = true }) },
	} {
		t.Run(name, func(t *testing.T) {
			c, err := decodeControl(signed.Body)
			if err != nil {
				t.Fatal(err)
			}
			mutate(&c)
			body, _ := encMode.Marshal(c.canonical())
			if string(body) == string(signed.Body) {
				t.Fatal("mutation did not change the body")
			}
			tampered, _ := Signed{Body: body, Signature: signed.Signature}.Encode()
			if _, err := VerifyChild([]*Verified{genesis}, tampered); !errors.Is(err, ErrInvalid) {
				t.Fatalf("tampered control accepted: %v", err)
			}
		})
	}
}

func TestWrongKeyRejected(t *testing.T) {
	alice, bob := newActor(t, true), newActor(t, false)
	bad := bob.p
	bad.ID = alice.p.ID // claims alice's device id with bob's key
	c := Control{Workspace: testWorkspace, Principals: []Principal{alice.p, bad}, Author: alice.p.ID}
	if err := c.Validate(); !errors.Is(err, ErrInvalid) {
		t.Fatalf("mismatched device id accepted: %v", err)
	}
	bad.ID = bob.p.ID
	bad.Signing = alice.p.Signing
	c.Principals = []Principal{alice.p, bad}
	if err := c.canonical().Validate(); !errors.Is(err, ErrInvalid) {
		t.Fatalf("mismatched signing key accepted: %v", err)
	}
}

func TestVerifyGenesisChecksTrustedDigest(t *testing.T) {
	alice := newActor(t, true)
	blob, d := genesisOf(t, alice)
	if _, err := VerifyGenesis(testWorkspace, blob, digest.FromString("other")); !errors.Is(err, ErrInvalid) {
		t.Fatalf("untrusted genesis accepted: %v", err)
	}
	if _, err := VerifyGenesis("0192f3a0-7c1e-7a55-9d3c-000000000000", blob, d); !errors.Is(err, ErrInvalid) {
		t.Fatalf("control of another workspace accepted: %v", err)
	}
}

func TestSuccessorMustFollowItsPredecessor(t *testing.T) {
	alice := newActor(t, true)
	blob, d := genesisOf(t, alice)
	genesis, _ := VerifyGenesis(testWorkspace, blob, d)
	wrong := *genesis
	wrong.Digest = digest.FromString("not the genesis")
	if _, err := VerifyChild([]*Verified{&wrong}, nextOf(t, genesis, alice, alice.p)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("successor of another predecessor accepted: %v", err)
	}
	skipped := *genesis
	skipped.Height = 5
	if _, err := VerifyChild([]*Verified{&skipped}, nextOf(t, genesis, alice, alice.p)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("height gap accepted: %v", err)
	}
}

func TestControlWithoutAdminIsRejected(t *testing.T) {
	alice, bob := newActor(t, true), newActor(t, false)
	if _, err := SignControl(Control{Workspace: testWorkspace, Principals: []Principal{bob.p}, Author: bob.p.ID}, bob.signer); !errors.Is(err, ErrInvalid) {
		t.Fatalf("control without admin: %v", err)
	}
	if _, err := SignControl(Control{Workspace: testWorkspace, Principals: []Principal{alice.p}, Author: alice.p.ID}, bob.signer); !errors.Is(err, ErrInvalid) {
		t.Fatalf("signer other than author: %v", err)
	}
}

// looseSigned has the same fields as Signed but encodes them body-first, which
// is valid CBOR but not the canonical key order.
type looseSigned struct {
	Body      []byte `cbor:"body"`
	Signature []byte `cbor:"sig"`
}

func TestNonCanonicalEncodingRejected(t *testing.T) {
	alice := newActor(t, true)
	blob, _ := genesisOf(t, alice)
	if _, err := DecodeSigned(blob); err != nil {
		t.Fatalf("canonical blob rejected: %v", err)
	}
	s, _ := DecodeSigned(blob)
	loose, err := cbor.Marshal(looseSigned(s))
	if err != nil {
		t.Fatal(err)
	}
	if string(loose) == string(blob) {
		t.Fatal("the loose encoding is the canonical one")
	}
	// Decoding alone succeeds; it is the canonical check that must reject it.
	var plain Signed
	if err := decMode.Unmarshal(loose, &plain); err != nil {
		t.Fatalf("test input is not valid CBOR: %v", err)
	}
	if _, err := DecodeSigned(loose); !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), "non-canonical") {
		t.Fatalf("non-canonical encoding accepted: %v", err)
	}
	if _, err := DecodeSigned(append(append([]byte{}, blob...), 0)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("trailing bytes accepted: %v", err)
	}
}

func TestOversizedObjectsAreRejectedBeforeParsing(t *testing.T) {
	if _, err := DecodeSigned(make([]byte, MaxSignedBytes+1)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("oversized object: %v", err)
	}
}

// forkOf signs two competing children of the genesis, each by its own admin choice.
func forkedControls(t *testing.T, alice, bob, carol actor) (genesis, a, b *Verified) {
	t.Helper()
	blob, d := genesisOf(t, alice)
	genesis, err := VerifyGenesis(testWorkspace, blob, d)
	if err != nil {
		t.Fatal(err)
	}
	withBob, err := VerifyChild([]*Verified{genesis}, nextOf(t, genesis, alice, alice.p, bob.p))
	if err != nil {
		t.Fatal(err)
	}
	// bob is an admin on one branch and carol joins on the other.
	adminBob := bob.p
	adminBob.Admin = true
	a, err = VerifyChild([]*Verified{withBob}, nextOf(t, withBob, alice, alice.p, adminBob))
	if err != nil {
		t.Fatal(err)
	}
	b, err = VerifyChild([]*Verified{withBob}, nextOf(t, withBob, alice, alice.p, bob.p, carol.p))
	if err != nil {
		t.Fatal(err)
	}
	return withBob, a, b
}

func resolution(t *testing.T, parents []*Verified, by actor, principals ...Principal) ([]byte, error) {
	t.Helper()
	ds := make([]digest.Digest, len(parents))
	var h uint64
	for i, p := range parents {
		ds[i] = p.Digest
		h = max(h, p.Height)
	}
	sortDigests(ds)
	blob, err := SignControl(Control{Workspace: testWorkspace, Parents: ds, Height: h + 1, Principals: principals, Author: by.p.ID}, by.signer)
	if err != nil {
		return nil, err
	}
	_, err = VerifyChild(parents, blob)
	return blob, err
}

func TestResolutionMayOnlyKeepWhatTheHeadsListed(t *testing.T) {
	alice, bob, carol, mallory := newActor(t, true), newActor(t, false), newActor(t, false), newActor(t, false)
	_, a, b := forkedControls(t, alice, bob, carol)
	parents := []*Verified{a, b}

	adminBob := bob.p
	adminBob.Admin = true
	if _, err := resolution(t, parents, alice, alice.p, adminBob, carol.p); err != nil {
		t.Fatalf("keeping everything the heads listed: %v", err)
	}
	if _, err := resolution(t, parents, alice, alice.p); err != nil {
		t.Fatalf("dropping principals: %v", err)
	}
	if _, err := resolution(t, parents, alice, alice.p, bob.p, carol.p, mallory.p); !errors.Is(err, ErrInvalid) {
		t.Fatalf("resolution added a principal: %v", err)
	}
	adminCarol := carol.p
	adminCarol.Admin = true
	if _, err := resolution(t, parents, alice, alice.p, bob.p, adminCarol); !errors.Is(err, ErrInvalid) {
		t.Fatalf("resolution promoted someone who was no admin on any head: %v", err)
	}
	swapped := bob.p
	swapped.Recipient = mallory.p.Recipient
	if _, err := resolution(t, parents, alice, alice.p, swapped); !errors.Is(err, ErrInvalid) {
		t.Fatalf("resolution changed a recipient: %v", err)
	}
}

func TestResolutionNeedsAnAdminOfEveryHead(t *testing.T) {
	alice, bob, carol := newActor(t, true), newActor(t, false), newActor(t, false)
	_, a, b := forkedControls(t, alice, bob, carol)
	// bob is an admin on a but only a member on b.
	adminBob := bob.p
	adminBob.Admin = true
	if _, err := resolution(t, []*Verified{a, b}, bob, alice.p, adminBob); !errors.Is(err, ErrInvalid) {
		t.Fatalf("resolution signed by an admin of only one head: %v", err)
	}
}

func TestResolutionMustNameAllItsParents(t *testing.T) {
	alice, bob, carol := newActor(t, true), newActor(t, false), newActor(t, false)
	_, a, b := forkedControls(t, alice, bob, carol)
	blob, err := resolution(t, []*Verified{a, b}, alice, alice.p)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyChild([]*Verified{a}, blob); !errors.Is(err, ErrInvalid) {
		t.Fatalf("resolution checked against a subset of its parents: %v", err)
	}
}
