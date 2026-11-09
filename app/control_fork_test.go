package app

import (
	"reflect"
	"testing"

	"github.com/enbu-net/enbu/app/apptest"
	"github.com/enbu-net/enbu/pkg/apperr"
	"github.com/enbu-net/enbu/pkg/storage"
	"github.com/enbu-net/enbu/pkg/wsp"
)

// Two admins who change the members at the same time fork the Control. A
// device that is not an admin of every head stops; the next ordinary operation
// of an admin of every head joins the fork, granting nothing that both sides
// did not.
func TestControlForkIsJoinedByAnAdminsNextOperation(t *testing.T) {
	alice := newAlice(t)
	bob := approved(t, alice)
	if err := alice.SetAdmin(bg, mustMember(t, alice, bob).DeviceID, true); err != nil {
		t.Fatal(err)
	}
	eve := approved(t, alice) // a plain member
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
		"members": func() error { _, err := eve.ListMembers(bg); return err },
		"list":    func() error { _, err := eve.ListSecrets(bg, "default"); return err },
		"write":   func() error { return eve.AddSecret(bg, "default", "X", "y") },
		"carol":   func() error { _, err := carol.ListMembers(bg); return err },
	} {
		if err := run(); !apperr.Is(err, apperr.CodeControlForked) {
			t.Fatalf("%s during a fork: %v", name, err)
		}
	}

	if err := alice.AddSecret(bg, "default", "AFTER", "ok"); err != nil {
		t.Fatalf("an admin's write during a fork: %v", err)
	}
	cur, err := alice.openControlView(bg)
	if err != nil {
		t.Fatal(err)
	}
	defer cur.Close()
	if len(cur.view.Heads) != 1 {
		t.Fatalf("heads after joining = %d", len(cur.view.Heads))
	}
	members, err := eve.ListMembers(bg)
	if err != nil {
		t.Fatal(err)
	}
	// carol and dave were each added on one side only, so neither survives.
	admins := map[string]bool{}
	for _, m := range members {
		admins[m.DeviceID] = m.Admin
	}
	want := map[string]bool{
		mustMember(t, alice, alice).DeviceID: true,
		mustMember(t, alice, bob).DeviceID:   true,
		mustMember(t, alice, eve).DeviceID:   false,
	}
	if !reflect.DeepEqual(admins, want) {
		t.Fatalf("members after joining = %v, want %v", admins, want)
	}
	if got := listOK(t, eve); got["AFTER"] != "ok" {
		t.Fatalf("eve after joining: %v", got)
	}
}

// An admin whose rights one side revoked is not an admin of every head, so it
// stops like any member until the remaining admin joins the fork.
func TestControlForkStopsAnAdminDemotedOnOneSide(t *testing.T) {
	alice := newAlice(t)
	bob := approved(t, alice)
	bobID := mustMember(t, alice, bob).DeviceID
	if err := alice.SetAdmin(bg, bobID, true); err != nil {
		t.Fatal(err)
	}
	dave := newDevice(t, alice)
	requestJoin(t, dave)
	daveEntry := principalOf(t, dave)

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
		for i := range c.Principals {
			if string(c.Principals[i].ID) == bobID {
				c.Principals[i].Admin = false
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := wsp.UpdateControl(bg, bs.store, bs.view, bs.signer, func(c *wsp.Control) error {
		c.Principals = append(c.Principals, daveEntry)
		return nil
	}); !apperr.Is(wspError(err), apperr.CodeControlForked) {
		t.Fatalf("the second concurrent change must report the fork: %v", err)
	}

	if _, err := bob.ListSecrets(bg, "default"); !apperr.Is(err, apperr.CodeControlForked) {
		t.Fatalf("a demoted admin joined the fork: %v", err)
	}
	if _, err := alice.ListSecrets(bg, "default"); err != nil {
		t.Fatal(err)
	}
	members, err := bob.ListMembers(bg)
	if err != nil {
		t.Fatal(err)
	}
	if len(members) != 2 {
		t.Fatalf("members after joining = %+v", members)
	}
	for _, m := range members {
		if m.DeviceID == bobID && m.Admin {
			t.Fatal("the join kept an admin right one side revoked")
		}
	}
}

// forkDroppingDave forks the Control: alice adds carol while bob, an admin
// from the older head, removes dave, a plain member who can read KEY. Either
// admin's next operation joins the fork, dropping dave.
func forkDroppingDave(t *testing.T) (alice, dave *App) {
	t.Helper()
	alice = newAlice(t)
	bob := approved(t, alice)
	if err := alice.SetAdmin(bg, mustMember(t, alice, bob).DeviceID, true); err != nil {
		t.Fatal(err)
	}
	dave = approved(t, alice)
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
	return alice, dave
}

// requireUnreadableBy checks that the current revision of default is signed
// under the current control and that dave can no longer decrypt it.
func requireUnreadableBy(t *testing.T, alice, dave *App) {
	t.Helper()
	cur, err := alice.openSession(bg)
	if err != nil {
		t.Fatal(err)
	}
	defer cur.Close()
	read, err := cur.readResource(bg, cur.resource("default"), nil, false)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, err := storage.ReadBlob(bg, alice.Storage, storage.KindState, read.heads[0].Scope(), read.heads[0].Digest, 0, storage.MaxPayloadBytes)
	if err != nil {
		t.Fatal(err)
	}
	d, err := loadDevice(dave.Identities, mustWorkspace(t, dave))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = d.Close() }()
	if _, err := decryptSecretsObject(ciphertext, d.Identity); err == nil {
		t.Fatal("the current revision is still encrypted for the member the resolution dropped")
	}
	if read.heads[0].Control != cur.head.Digest {
		t.Fatal("the revision was not re-signed under the resolved control")
	}
}

// Resolving a fork can drop a member who could read the existing secrets. The
// ciphertext must then be re-encrypted without them, exactly as a removal does.
func TestResolvingAControlForkReencryptsForTheSurvivors(t *testing.T) {
	alice, dave := forkDroppingDave(t)

	// alice's next operation joins the fork.
	if got := listOK(t, alice); got["KEY"] != "v1" {
		t.Fatalf("alice after resolving: %v", got)
	}
	// dave was not on one of the sides, so the resolution drops him and he can
	// no longer decrypt what is stored now.
	if _, err := dave.ListSecrets(bg, "default"); !apperr.Is(err, apperr.CodeNotMember) {
		t.Fatalf("a dropped member still reads: %v", err)
	}
	requireUnreadableBy(t, alice, dave)
}

// The operation that joined the fork fails, even a read, when re-encryption
// does not finish: the join is not retried, so this is the only moment the
// admin learns to run sync. Sync then finishes the re-encryption.
func TestResolvingAControlForkReportsIncompleteReencryption(t *testing.T) {
	alice, dave := forkDroppingDave(t)
	base := alice.Storage
	alice.Storage = failStatePublishes(base, nil)
	if _, err := alice.ListSecrets(bg, "default"); !apperr.Is(err, apperr.CodeReencryptIncomplete) {
		t.Fatalf("a read that joined the fork without re-encrypting: %v", err)
	}
	alice.Storage = base
	cur, err := alice.openControlView(bg)
	if err != nil {
		t.Fatal(err)
	}
	cur.Close()
	if cur.head == nil {
		t.Fatal("the join was not published")
	}
	if err := alice.SyncSecrets(bg, "default"); err != nil {
		t.Fatal(err)
	}
	requireUnreadableBy(t, alice, dave)
}

// An admin whose keys cannot be loaded learns why instead of only seeing the
// fork it could otherwise have joined.
func TestControlForkReportsAnAdminsUnusableKeys(t *testing.T) {
	alice, _ := forkDroppingDave(t)
	alice.Identities = lostBackend{alice.Identities.(*apptest.Identities)}
	_, err := alice.ListMembers(bg)
	requireIdentityUnavailable(t, err, "keyring unavailable")
}
