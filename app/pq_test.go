package app

import (
	"strings"
	"testing"
	"time"

	"github.com/enbu-net/enbu/pkg/age"
	"github.com/enbu-net/enbu/pkg/apperr"
	"github.com/enbu-net/enbu/pkg/identity"
	"github.com/enbu-net/enbu/pkg/storage"
	"github.com/enbu-net/enbu/pkg/wsp"
)

// pqKeys is the real identity store, which creates hybrid ML-KEM-768 +
// X25519 keyring identities by default.
func pqKeys(t *testing.T) *identity.Manager {
	t.Helper()
	return &identity.Manager{Dir: t.TempDir(), Mode: "keyring", Vault: identityVault{}}
}

// classicalKeys is the identity store of a device set up before hybrid keys.
func classicalKeys(t *testing.T) *identity.Manager {
	t.Helper()
	return &identity.Manager{Dir: t.TempDir(), Mode: "keyring", Vault: identityVault{}, Classical: true}
}

// stanzas returns the age header of the latest default revision.
func stanzas(t *testing.T, a *App) string {
	t.Helper()
	s, err := a.openSession(bg)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	read, err := s.readResource(bg, s.resource("default"), nil, false)
	if err != nil || len(read.heads) != 1 {
		t.Fatalf("read: %v", err)
	}
	h := read.heads[0]
	ciphertext, err := storage.ReadBlob(bg, a.Storage, storage.KindState, h.Scope(), h.Digest, 0, storage.MaxPayloadBytes)
	if err != nil {
		t.Fatal(err)
	}
	header, _, _ := strings.Cut(string(ciphertext), "\n---")
	return header
}

func mustRead(t *testing.T, a *App, key, want string) {
	t.Helper()
	got, err := a.ListSecrets(bg, "default")
	if err != nil || got[key] != want {
		t.Fatalf("%s = %q, %v; want %q", key, got[key], err, want)
	}
}

// A workspace whose members all hold hybrid keys stores only post-quantum
// stanzas. A classical member joining downgrades the next revision to
// classical, and every member can still read it.
func TestPostQuantumWorkspaceEndToEnd(t *testing.T) {
	alice := &App{Storage: newMemRegistry(), Identities: pqKeys(t), CheckpointDir: t.TempDir(),
		TokenProvider: &staticTokenProvider{token: "tok", username: "alice"}, RepoDetector: &staticRepoDetector{owner: "owner", repo: "repo"}}
	prepareApp(t, alice, "default")
	if _, err := alice.InitializeRepository(bg); err != nil {
		t.Fatal(err)
	}
	if err := alice.AddSecret(bg, "default", "KEY", "v1"); err != nil {
		t.Fatal(err)
	}
	if h := stanzas(t, alice); strings.Count(h, "-> mlkem768x25519 ") != 1 || strings.Contains(h, "-> X25519 ") {
		t.Fatalf("founder revision is not post-quantum:\n%.200s", h)
	}

	bob := newDevice(t, alice)
	bob.Identities = pqKeys(t)
	if err := alice.ApproveMember(bg, requestJoin(t, bob).DeviceID); err != nil {
		t.Fatal(err)
	}
	mustRead(t, bob, "KEY", "v1")
	if h := stanzas(t, alice); strings.Count(h, "-> mlkem768x25519 ") != 2 {
		t.Fatalf("approval did not re-encrypt for both hybrid members:\n%.200s", h)
	}
	if got := mustMember(t, alice, bob).Recipient; !strings.HasPrefix(got, "age1pq1") {
		t.Fatalf("bob's recipient %.16s is not hybrid", got)
	}

	carol := newDevice(t, alice) // a classical X25519 member
	if err := alice.ApproveMember(bg, requestJoin(t, carol).DeviceID); err != nil {
		t.Fatal(err)
	}
	if h := stanzas(t, alice); strings.Count(h, "-> mlkem768x25519 ") != 2 || strings.Count(h, "-> X25519 ") != 1 {
		t.Fatalf("mixed revision:\n%.200s", h)
	}
	for _, a := range []*App{alice, bob, carol} {
		mustRead(t, a, "KEY", "v1")
	}
}

func newFounder(t *testing.T, keys *identity.Manager) *App {
	t.Helper()
	a := &App{Storage: newMemRegistry(), Identities: keys, CheckpointDir: t.TempDir(),
		TokenProvider: &staticTokenProvider{token: "tok", username: "alice"}, RepoDetector: &staticRepoDetector{owner: "owner", repo: "repo"}}
	prepareApp(t, a, "default")
	if _, err := a.InitializeRepository(bg); err != nil {
		t.Fatal(err)
	}
	return a
}

// Existing members move to hybrid keys one by one. A member's update waits for
// an admin; an admin's own update applies at once. Once everyone has
// upgraded, revisions carry only post-quantum stanzas.
func TestUpgradeIdentityMovesAWorkspaceToPostQuantum(t *testing.T) {
	alice := newFounder(t, classicalKeys(t))
	if err := alice.AddSecret(bg, "default", "KEY", "v1"); err != nil {
		t.Fatal(err)
	}
	bob := newDevice(t, alice)
	bob.Identities = classicalKeys(t)
	bobDevice := requestJoin(t, bob).DeviceID
	if err := alice.ApproveMember(bg, bobDevice); err != nil {
		t.Fatal(err)
	}
	if h := stanzas(t, alice); strings.Count(h, "-> X25519 ") != 2 {
		t.Fatalf("classical workspace:\n%.200s", h)
	}

	res, err := bob.UpgradeIdentity(bg)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Pending || res.Algorithm != "MLKEM768-X25519" || !strings.HasPrefix(res.Recipient, "age1pq1") || res.DeviceID != bobDevice {
		t.Fatalf("member upgrade: %+v", res)
	}
	mustRead(t, bob, "KEY", "v1") // the current key still works while pending
	requests, err := alice.ListJoinRequests(bg)
	if err != nil || len(requests) != 1 || !requests[0].KeyUpdate || requests[0].DeviceID != bobDevice || requests[0].Recipient != res.Recipient {
		t.Fatalf("requests = %+v, %v", requests, err)
	}
	if err := alice.ApproveMember(bg, bobDevice); err != nil {
		t.Fatal(err)
	}
	if h := stanzas(t, alice); strings.Count(h, "-> X25519 ") != 1 || strings.Count(h, "-> mlkem768x25519 ") != 1 {
		t.Fatalf("after bob's update:\n%.200s", h)
	}
	mustRead(t, bob, "KEY", "v1")
	if info, err := bob.Identities.Info(mustWorkspace(t, bob)); err != nil || info.Recipient != res.Recipient {
		t.Fatalf("bob did not switch to the approved key: %+v %v", info, err)
	}
	if ids, err := LoadIdentities(bob.Identities, mustWorkspace(t, bob)); err != nil || len(ids) != 2 {
		t.Fatalf("bob should keep the replaced key for older revisions: %d %v", len(ids), err)
	} else {
		CloseIdentities(ids)
	}

	res, err = alice.UpgradeIdentity(bg)
	if err != nil {
		t.Fatal(err)
	}
	if res.Pending {
		t.Fatal("an admin's own update should apply at once")
	}
	if h := stanzas(t, alice); strings.Count(h, "-> mlkem768x25519 ") != 2 || strings.Contains(h, "-> X25519 ") {
		t.Fatalf("after every member upgraded:\n%.200s", h)
	}
	for _, a := range []*App{alice, bob} {
		mustRead(t, a, "KEY", "v1")
	}
	members, err := alice.ListMembers(bg)
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range members {
		if !m.PostQuantum {
			t.Fatalf("%s is not post-quantum", m.Fingerprint)
		}
	}
	// Bob's join request and both key updates are still in storage. None of
	// them may be offered again: that would swap a key back.
	if requests, err := alice.ListJoinRequests(bg); err != nil || len(requests) != 0 {
		t.Fatalf("stale requests offered: %+v %v", requests, err)
	}
	if err := alice.ApproveMember(bg, bobDevice); !apperr.Is(err, apperr.CodeInvalidArgument) {
		t.Fatalf("approving a member with no update: %v", err)
	}
	if _, err := bob.UpgradeIdentity(bg); !apperr.Is(err, apperr.CodeInvalidArgument) {
		t.Fatalf("upgrading twice: %v", err)
	}
}

// A key update names the recipient it replaces. Once that recipient is gone,
// for example because an admin re-approved the device differently, the update
// is no longer offered.
func TestKeyUpdateForAnotherDeviceIsIgnored(t *testing.T) {
	alice := newFounder(t, classicalKeys(t))
	mallory := newDevice(t, alice)
	mallory.Identities = classicalKeys(t)
	requestJoin(t, mallory)
	ws := mustWorkspace(t, alice)
	signer, err := mallory.Identities.LoadSigner(ws)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = signer.Close() }()
	pq, err := age.GenerateHybridKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	// A non-member filing a "key update" for alice's recipient gets nothing:
	// the request is signed by mallory's key, so it names mallory's device.
	blob, err := wsp.NewKeyUpdateRequest(ws, pq.PublicKey, mustRecipient(t, alice), time.Now(), signer)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := wsp.PublishJoinRequest(bg, alice.Storage, blob); err != nil {
		t.Fatal(err)
	}
	requests, err := alice.ListJoinRequests(bg)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range requests {
		if r.KeyUpdate {
			t.Fatalf("a non-member's key update was offered: %+v", r)
		}
	}
}
