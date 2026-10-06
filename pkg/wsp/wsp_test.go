package wsp

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"testing"

	"filippo.io/age"
	"github.com/enbu-net/enbu/pkg/signing"
	"github.com/enbu-net/enbu/pkg/storage"
	"github.com/enbu-net/enbu/pkg/storage/storagetest"
	"github.com/opencontainers/go-digest"
)

const testWorkspace = "0192f3a0-7c1e-7a55-9d3c-5f6a1b2c3d4e"

type actor struct {
	signer signing.Signer
	p      Principal
}

func newActor(t *testing.T, admin bool) actor {
	t.Helper()
	_, k, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s := signing.NewEd25519Signer(k)
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	return actor{signer: s, p: Principal{ID: s.Public().DeviceID(), Signing: s.Public(), Recipient: id.Recipient().String(), Admin: admin}}
}

// workspace creates a store whose genesis is founded by alice.
func workspace(t *testing.T) (*storage.Store, actor, digest.Digest) {
	t.Helper()
	store := storagetest.NewMemory()
	alice := newActor(t, true)
	v, err := CreateControl(context.Background(), store, testWorkspace, alice.p, alice.signer)
	if err != nil {
		t.Fatal(err)
	}
	return store, alice, v.Digest
}

func addMember(t *testing.T, store *storage.Store, genesis digest.Digest, by, who actor) *Verified {
	t.Helper()
	head, err := LoadControl(context.Background(), store, testWorkspace, genesis, nil)
	if err != nil {
		t.Fatal(err)
	}
	v, err := UpdateControl(context.Background(), store, head, by.signer, func(c *Control) error {
		c.Principals = append(c.Principals, who.p)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestControlGrowsOnlyThroughSignedChain(t *testing.T) {
	store, alice, genesis := workspace(t)
	bob := newActor(t, false)
	v := addMember(t, store, genesis, alice, bob)
	head, err := LoadControl(context.Background(), store, testWorkspace, genesis, nil)
	if err != nil {
		t.Fatal(err)
	}
	if head.Digest != v.Digest || head.Generation != 1 || len(head.Recipients()) != 2 {
		t.Fatalf("unexpected head: %+v", head.Control)
	}
	if _, ok := head.Principal(bob.p.ID); !ok {
		t.Fatal("bob is not a principal")
	}
}

func TestRecipientInjectionIsIgnored(t *testing.T) {
	store, alice, genesis := workspace(t)
	attacker := newActor(t, false)
	ctx := context.Background()
	// Anything an attacker can write under other names has no effect on the set.
	for _, name := range []string{"recipient-" + attacker.p.Recipient, "request-" + string(attacker.p.ID)} {
		d, _ := store.Blobs.Put(ctx, bytesReader([]byte(attacker.p.Recipient)))
		if err := store.Refs.Put(ctx, name, d, ""); err != nil {
			t.Fatal(err)
		}
	}
	head, err := LoadControl(ctx, store, testWorkspace, genesis, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := head.Recipients(); len(got) != 1 || got[0] != alice.p.Recipient {
		t.Fatalf("recipient set changed: %v", got)
	}
}

func TestAttackerControlRejected(t *testing.T) {
	store, alice, genesis := workspace(t)
	ctx := context.Background()
	head, _ := LoadControl(ctx, store, testWorkspace, genesis, nil)
	mallory := newActor(t, true)
	forged := Control{Workspace: testWorkspace, Generation: 1, Previous: head.Digest, Author: mallory.p.ID,
		Principals: []Principal{alice.p, mallory.p}}
	blob, err := SignControl(forged, mallory.signer)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyNext(head.Verified, blob); !errors.Is(err, ErrInvalid) {
		t.Fatalf("control signed by an outsider was accepted: %v", err)
	}
	// Pointing the head ref at it makes the load fail rather than trust it.
	if err := putControl(ctx, store, blob, head.Version); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadControl(ctx, store, testWorkspace, genesis, nil); !errors.Is(err, ErrInvalid) {
		t.Fatalf("forged head accepted: %v", err)
	}
}

func TestMemberCannotChangeControl(t *testing.T) {
	store, alice, genesis := workspace(t)
	bob := newActor(t, false)
	addMember(t, store, genesis, alice, bob)
	head, _ := LoadControl(context.Background(), store, testWorkspace, genesis, nil)
	if _, err := UpdateControl(context.Background(), store, head, bob.signer, func(*Control) error { return nil }); err == nil {
		t.Fatal("non-admin updated the control")
	}
	// Even if bob forges one by hand, verification fails.
	forged := head.Control
	forged.Generation, forged.Previous, forged.Author = 2, head.Digest, bob.p.ID
	blob, err := SignControl(forged, bob.signer)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyNext(head.Verified, blob); !errors.Is(err, ErrInvalid) {
		t.Fatalf("member-signed control accepted: %v", err)
	}
}

func TestControlTampering(t *testing.T) {
	store, alice, genesis := workspace(t)
	bob := newActor(t, false)
	addMember(t, store, genesis, alice, bob)
	ctx := context.Background()
	d, _, _ := store.Refs.Get(ctx, ControlRef)
	blob, _ := readBlob(ctx, store, d)
	genBlob, _ := readBlob(ctx, store, genesis)
	genesisV, err := VerifyGenesis(testWorkspace, genBlob, genesis)
	if err != nil {
		t.Fatal(err)
	}
	signed, _ := DecodeSigned(blob)
	mallory := newActor(t, false)
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
			if _, err := VerifyNext(genesisV, tampered); !errors.Is(err, ErrInvalid) {
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

func TestGenesisMustMatchTrustedDigest(t *testing.T) {
	store, _, genesis := workspace(t)
	ctx := context.Background()
	other := digest.FromString("other")
	if _, err := LoadControl(ctx, store, testWorkspace, other, nil); err == nil {
		t.Fatal("untrusted genesis accepted")
	}
	if _, err := LoadControl(ctx, store, "0192f3a0-7c1e-7a55-9d3c-000000000000", genesis, nil); err == nil {
		t.Fatal("control of another workspace accepted")
	}
}

func TestNonCanonicalEncodingRejected(t *testing.T) {
	_, alice, _ := workspace(t)
	blob, err := SignControl(Control{Workspace: testWorkspace, Principals: []Principal{alice.p}, Author: alice.p.ID}, alice.signer)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeSigned(blob); err != nil {
		t.Fatalf("canonical blob rejected: %v", err)
	}
	// Same map, keys in the opposite (non-canonical) order.
	s, _ := DecodeSigned(blob)
	loose := []byte{0xa2, 0x63, 's', 'i', 'g', 0x40 + byte(len(s.Signature))}
	loose = append(loose, s.Signature...)
	loose = append(loose, 0x64, 'b', 'o', 'd', 'y', 0x58, byte(len(s.Body)))
	loose = append(loose, s.Body...)
	if _, err := DecodeSigned(loose); !errors.Is(err, ErrInvalid) {
		t.Fatalf("non-canonical encoding accepted: %v", err)
	}
	// Trailing bytes after the object.
	if _, err := DecodeSigned(append(append([]byte{}, blob...), 0)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("trailing bytes accepted: %v", err)
	}
}

func TestRollbackAndForkRejected(t *testing.T) {
	store, alice, genesis := workspace(t)
	ctx := context.Background()
	bob := newActor(t, false)
	v1 := addMember(t, store, genesis, alice, bob)
	carol := newActor(t, false)
	head, _ := LoadControl(ctx, store, testWorkspace, genesis, nil)
	v2, err := UpdateControl(ctx, store, head, alice.signer, func(c *Control) error {
		c.Principals = append(c.Principals, carol.p)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	cp := &Checkpoint{Generation: v2.Generation, Digest: v2.Digest}

	// Storage rewinds the head to generation 1.
	_, version, _ := store.Refs.Get(ctx, ControlRef)
	if err := store.Refs.Put(ctx, ControlRef, v1.Digest, version); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadControl(ctx, store, testWorkspace, genesis, cp); !errors.Is(err, ErrRollback) {
		t.Fatalf("rolled back head accepted: %v", err)
	}
	// Without a checkpoint the same old head is indistinguishable from current.
	if _, err := LoadControl(ctx, store, testWorkspace, genesis, nil); err != nil {
		t.Fatalf("old head without checkpoint: %v", err)
	}

	// A fork at the same generation with a different digest.
	dave := newActor(t, false)
	h1, _ := LoadControl(ctx, store, testWorkspace, genesis, nil)
	fork, err := UpdateControl(ctx, store, h1, alice.signer, func(c *Control) error {
		c.Principals = append(c.Principals, dave.p)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if fork.Generation != v2.Generation || fork.Digest == v2.Digest {
		t.Fatal("test setup did not create a fork")
	}
	if _, err := LoadControl(ctx, store, testWorkspace, genesis, cp); !errors.Is(err, ErrRollback) {
		t.Fatalf("fork accepted: %v", err)
	}
}

func TestCheckpointAnchorsAndAdvances(t *testing.T) {
	store, alice, genesis := workspace(t)
	ctx := context.Background()
	bob := newActor(t, false)
	v1 := addMember(t, store, genesis, alice, bob)
	cp := &Checkpoint{Generation: v1.Generation, Digest: v1.Digest}
	head, err := LoadControl(ctx, store, testWorkspace, genesis, cp)
	if err != nil || head.Digest != v1.Digest {
		t.Fatalf("head at checkpoint: %v", err)
	}
	carol := newActor(t, false)
	v2, err := UpdateControl(ctx, store, head, alice.signer, func(c *Control) error {
		c.Principals = append(c.Principals, carol.p)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	head, err = LoadControl(ctx, store, testWorkspace, genesis, cp)
	if err != nil || head.Digest != v2.Digest {
		t.Fatalf("advance past checkpoint: %v", err)
	}
}

func TestConcurrentUpdateConflicts(t *testing.T) {
	store, alice, genesis := workspace(t)
	ctx := context.Background()
	head, _ := LoadControl(ctx, store, testWorkspace, genesis, nil)
	if _, err := UpdateControl(ctx, store, head, alice.signer, func(c *Control) error { c.Principals = append(c.Principals, newActor(t, false).p); return nil }); err != nil {
		t.Fatal(err)
	}
	// head still carries the old ref version.
	_, err := UpdateControl(ctx, store, head, alice.signer, func(c *Control) error { c.Principals = append(c.Principals, newActor(t, false).p); return nil })
	if !errors.Is(err, storage.ErrConflict) {
		t.Fatalf("stale update: %v", err)
	}
	if _, err := CreateControl(ctx, store, testWorkspace, alice.p, alice.signer); !errors.Is(err, storage.ErrConflict) {
		t.Fatalf("second genesis: %v", err)
	}
}

func TestLastAdminCannotBeRemoved(t *testing.T) {
	store, alice, genesis := workspace(t)
	head, _ := LoadControl(context.Background(), store, testWorkspace, genesis, nil)
	bob := newActor(t, false)
	_, err := UpdateControl(context.Background(), store, head, alice.signer, func(c *Control) error {
		c.Principals = []Principal{bob.p}
		return nil
	})
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("control without admin: %v", err)
	}
}

func bytesReader(b []byte) *bytes.Reader { return bytes.NewReader(b) }

func writeFile(path, s string) error { return os.WriteFile(path, []byte(s), 0o600) }
