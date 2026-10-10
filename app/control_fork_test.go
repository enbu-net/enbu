package app

import (
	"testing"

	"github.com/enbu-net/enbu/pkg/apperr"
	"github.com/enbu-net/enbu/pkg/storage"
	"github.com/enbu-net/enbu/pkg/wsp"
)

// Two admins who change the members at the same time fork the Control. Nothing
// proceeds until an admin resolves it, and the resolution grants nothing that
// both sides did not.
func TestControlForkStopsEverythingUntilAnAdminResolvesIt(t *testing.T) {
	alice := newAlice(t)
	bob := approved(t, alice)
	if err := alice.SetAdmin(bg, mustMember(t, alice, bob).DeviceID, true); err != nil {
		t.Fatal(err)
	}
	carol, dave := newDevice(t, alice), newDevice(t, alice)
	requestJoin(t, carol)
	requestJoin(t, dave)
	carolEntry, daveEntry := principalOf(t, carol), principalOf(t, dave)

	as, err := alice.openSession(bg)
	if err != nil {
		t.Fatal(err)
	}
	defer as.Close()
	bs, err := bob.openSession(bg)
	if err != nil {
		t.Fatal(err)
	}
	defer bs.Close()
	if _, err := wsp.UpdateControl(bg, as.store, as.view, as.signer, func(c *wsp.Control) error {
		c.Principals = append(c.Principals, carolEntry)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	// bob still works from the head before alice's change.
	if _, err := wsp.UpdateControl(bg, bs.store, bs.view, bs.signer, func(c *wsp.Control) error {
		c.Principals = append(c.Principals, daveEntry)
		return nil
	}); !apperr.Is(wspError(err), apperr.CodeControlForked) {
		t.Fatalf("the second concurrent change must report the fork: %v", err)
	}

	for name, run := range map[string]func() error{
		"members": func() error { _, err := alice.ListMembers(bg); return err },
		"list":    func() error { _, err := alice.ListSecrets(bg, "default"); return err },
		"write":   func() error { return alice.AddSecret(bg, "default", "X", "y") },
		"approve": func() error { return alice.ApproveMember(bg, string(carolEntry.ID)) },
	} {
		if err := run(); !apperr.Is(err, apperr.CodeControlForked) {
			t.Fatalf("%s during a fork: %v", name, err)
		}
	}
	if err := carol.ResolveControlFork(bg); err == nil {
		t.Fatal("a device that is not a member resolved the fork")
	}

	if err := alice.ResolveControlFork(bg); err != nil {
		t.Fatal(err)
	}
	members, err := alice.ListMembers(bg)
	if err != nil {
		t.Fatal(err)
	}
	// carol and dave were each added on one side only, so neither survives.
	if len(members) != 2 {
		t.Fatalf("members after resolving = %+v", members)
	}
	for _, m := range members {
		if m.DeviceID == string(carolEntry.ID) || m.DeviceID == string(daveEntry.ID) {
			t.Fatalf("a one-sided addition survived the resolution: %+v", m)
		}
	}
	if err := alice.AddSecret(bg, "default", "AFTER", "ok"); err != nil {
		t.Fatalf("writing after the resolution: %v", err)
	}
	if err := alice.ResolveControlFork(bg); !apperr.Is(err, apperr.CodeInvalidArgument) {
		t.Fatalf("resolving a Control that is not forked: %v", err)
	}
}

// Resolving a fork can drop a member who could read the existing secrets. The
// ciphertext must then be re-encrypted without them, exactly as a removal does.
func TestResolvingAControlForkReencryptsForTheSurvivors(t *testing.T) {
	alice := newAlice(t)
	bob := approved(t, alice)
	if err := alice.SetAdmin(bg, mustMember(t, alice, bob).DeviceID, true); err != nil {
		t.Fatal(err)
	}
	dave := approved(t, alice) // a plain member who can read KEY today
	carol := newDevice(t, alice)
	requestJoin(t, carol)
	carolEntry := principalOf(t, carol)
	daveID := mustMember(t, alice, dave).DeviceID

	as, err := alice.openSession(bg)
	if err != nil {
		t.Fatal(err)
	}
	defer as.Close()
	bs, err := bob.openSession(bg)
	if err != nil {
		t.Fatal(err)
	}
	defer bs.Close()
	if _, err := wsp.UpdateControl(bg, as.store, as.view, as.signer, func(c *wsp.Control) error {
		c.Principals = append(c.Principals, carolEntry)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	// bob, from the older head, removes dave.
	if _, err := wsp.UpdateControl(bg, bs.store, bs.view, bs.signer, func(c *wsp.Control) error {
		kept := c.Principals[:0:0]
		for _, p := range c.Principals {
			if string(p.ID) != daveID {
				kept = append(kept, p)
			}
		}
		c.Principals = kept
		return nil
	}); !apperr.Is(wspError(err), apperr.CodeControlForked) {
		t.Fatalf("the concurrent change must report the fork: %v", err)
	}

	if err := alice.ResolveControlFork(bg); err != nil {
		t.Fatal(err)
	}
	if got := listOK(t, alice); got["KEY"] != "v1" {
		t.Fatalf("alice after resolving: %v", got)
	}
	// dave was not on one of the sides, so the resolution drops him and he can
	// no longer decrypt what is stored now.
	if _, err := dave.ListSecrets(bg, "default"); !apperr.Is(err, apperr.CodeNotMember) {
		t.Fatalf("a dropped member still reads: %v", err)
	}
	cur, err := alice.openSession(bg)
	if err != nil {
		t.Fatal(err)
	}
	defer cur.Close()
	read, err := cur.readResource(bg, "default", nil, false)
	if err != nil {
		t.Fatal(err)
	}
	o, err := alice.Storage.Fetch(bg, storage.KindState, read.heads[0].Scope(), read.heads[0].Digest)
	if err != nil {
		t.Fatal(err)
	}
	ids, err := LoadIdentities(dave.Identities, mustWorkspace(t, dave))
	if err != nil {
		t.Fatal(err)
	}
	defer CloseIdentities(ids)
	if _, err := decryptSecretsObject(o.Cipher, ids...); err == nil {
		t.Fatal("the current revision is still encrypted for the member the resolution dropped")
	}
	if read.heads[0].Control != cur.head.Digest {
		t.Fatal("the revision was not re-signed under the resolved control")
	}
}
