package app

import (
	"bytes"
	"context"
	"reflect"
	"testing"

	"github.com/enbu-net/enbu/pkg/age"
	"github.com/enbu-net/enbu/pkg/apperr"
	"github.com/enbu-net/enbu/pkg/bundle"
	"github.com/enbu-net/enbu/pkg/config"
	"github.com/enbu-net/enbu/pkg/signing"
	"github.com/enbu-net/enbu/pkg/wsp"
)

var bg = context.Background()

// newDevice is another machine of the same repository: it shares the storage
// and the committed enbu.toml (including control_genesis) but has its own keys
// and its own local checkpoints.
func newDevice(t *testing.T, alice *App) *App {
	t.Helper()
	b := &App{Storage: alice.Storage, Identities: newMemKeyStore(), CheckpointDir: t.TempDir(), RepositoryDir: t.TempDir(),
		TokenProvider: &staticTokenProvider{token: "tok", username: "bob"}, RepoDetector: &staticRepoDetector{owner: "owner", repo: "repo"}}
	cfg, err := alice.loadProject()
	if err != nil {
		t.Fatal(err)
	}
	if err := config.SaveProjectTo(b.RepositoryDir, cfg); err != nil {
		t.Fatal(err)
	}
	return b
}

// approved returns a device that has joined and been approved by alice.
func approved(t *testing.T, alice *App) *App {
	t.Helper()
	bob := newDevice(t, alice)
	res, err := bob.InitializeRepository(bg)
	if err != nil || !res.Pending {
		t.Fatalf("join: %+v %v", res, err)
	}
	if err := alice.ApproveMember(bg, res.DeviceID); err != nil {
		t.Fatal(err)
	}
	if res, err = bob.InitializeRepository(bg); err != nil || res.Pending {
		t.Fatalf("after approval: %+v %v", res, err)
	}
	return bob
}

func newAlice(t *testing.T) *App {
	t.Helper()
	return newTestApp(t, "owner", "repo", "default", mustKeyPair(t), map[string]string{"KEY": "v1"})
}

func TestJoinApproveAndShareSecrets(t *testing.T) {
	alice := newAlice(t)
	bob := newDevice(t, alice)
	res, err := bob.InitializeRepository(bg)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Pending || res.Fingerprint == "" || res.Mode != "join" || !res.HasSecrets {
		t.Fatalf("join result: %+v", res)
	}
	// A pending device is not a principal: it can neither read nor write.
	if _, err := bob.ListSecrets(bg, "default"); !apperr.Is(err, apperr.CodeNotMember) {
		t.Fatalf("pending device read secrets: %v", err)
	}
	if err := bob.AddSecret(bg, "default", "BOB", "x"); !apperr.Is(err, apperr.CodeNotMember) {
		t.Fatalf("pending device wrote secrets: %v", err)
	}
	// Alice picks bob from the list.
	reqs, err := alice.ListJoinRequests(bg)
	if err != nil || len(reqs) != 1 || reqs[0].DeviceID != res.DeviceID || reqs[0].Fingerprint != res.Fingerprint {
		t.Fatalf("requests: %+v %v", reqs, err)
	}
	if err := alice.ApproveMember(bg, reqs[0].DeviceID); err != nil {
		t.Fatal(err)
	}
	if reqs, _ = alice.ListJoinRequests(bg); len(reqs) != 0 {
		t.Fatalf("approved request still listed: %+v", reqs)
	}
	// Approval re-encrypts, so bob decrypts what alice wrote before.
	got, err := bob.ListSecrets(bg, "default")
	if err != nil || !reflect.DeepEqual(got, map[string]string{"KEY": "v1"}) {
		t.Fatalf("bob reads: %v %v", got, err)
	}
	if err := bob.AddSecret(bg, "default", "BOB", "x"); err != nil {
		t.Fatal(err)
	}
	if got, err = alice.ListSecrets(bg, "default"); err != nil || got["BOB"] != "x" {
		t.Fatalf("alice reads bob's write: %v %v", got, err)
	}
	members, err := alice.ListMembers(bg)
	if err != nil || len(members) != 2 {
		t.Fatalf("members: %+v %v", members, err)
	}
	selfCount := 0
	for _, m := range members {
		if m.Self {
			selfCount++
		}
	}
	if selfCount != 1 {
		t.Fatalf("self flag: %+v", members)
	}
}

func TestMemberCannotApprove(t *testing.T) {
	alice := newAlice(t)
	bob := approved(t, alice)
	carol := newDevice(t, alice)
	res, err := carol.InitializeRepository(bg)
	if err != nil {
		t.Fatal(err)
	}
	if err := bob.ApproveMember(bg, res.DeviceID); !apperr.Is(err, apperr.CodeAccessDenied) {
		t.Fatalf("member approved a device: %v", err)
	}
	if err := alice.SetAdmin(bg, mustMember(t, alice, bob).DeviceID, true); err != nil {
		t.Fatal(err)
	}
	if err := bob.ApproveMember(bg, res.DeviceID); err != nil {
		t.Fatalf("promoted admin could not approve: %v", err)
	}
}

func mustMember(t *testing.T, observer, who *App) MemberInfo {
	t.Helper()
	ws, _ := who.WorkspaceID()
	want := who.selfDevice(ws)
	members, err := observer.ListMembers(bg)
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range members {
		if m.DeviceID == string(want) {
			return m
		}
	}
	t.Fatalf("%s is not a member", want)
	return MemberInfo{}
}

// Storage write access alone must not make anyone a recipient.
func TestRecipientInjection(t *testing.T) {
	alice := newAlice(t)
	attacker := mustKeyPair(t)
	for _, name := range []string{"recipient-" + attacker.PublicKey, "recipient-0000"} {
		if err := putRef(bg, alice.Storage, name, []byte(attacker.PublicKey), ""); err != nil {
			t.Fatal(err)
		}
	}
	if err := alice.AddSecret(bg, "default", "NEW", "secret"); err != nil {
		t.Fatal(err)
	}
	recipients, err := alice.ListRecipients(bg)
	if err != nil || len(recipients) != 1 || recipients[0].PublicKey == attacker.PublicKey {
		t.Fatalf("recipients: %+v %v", recipients, err)
	}
	// The ciphertext alice just wrote cannot be opened with the attacker's key.
	s, err := alice.openSession(bg)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	read, err := s.readState(bg, secretsTag("default"), "default", true)
	if err != nil {
		t.Fatal(err)
	}
	ct, err := readBlob(bg, alice.Storage, read.state.Ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := age.Decrypt(ct, attacker.Identity); err == nil {
		t.Fatal("injected recipient can decrypt")
	}
}

// A request that is not signed by the device it names is only noise.
func TestForgedJoinRequestsAreIgnored(t *testing.T) {
	alice := newAlice(t)
	mallory, victim := newDevice(t, alice), newDevice(t, alice)
	mRes, err := mallory.InitializeRepository(bg)
	if err != nil {
		t.Fatal(err)
	}
	vRes, err := victim.InitializeRepository(bg)
	if err != nil {
		t.Fatal(err)
	}
	genuine, _, err := getRef(bg, alice.Storage, wsp.JoinRequestRef(signing.DeviceID(mRes.DeviceID)))
	if err != nil {
		t.Fatal(err)
	}
	// Mallory's genuine bytes are planted under the victim's device id, and
	// under names that are not device ids at all.
	victimRef := wsp.JoinRequestRef(signing.DeviceID(vRes.DeviceID))
	_, v, _ := getRef(bg, alice.Storage, victimRef)
	if err := putRef(bg, alice.Storage, victimRef, genuine, v); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"request-not-a-device", "request-" + mRes.DeviceID[:10]} {
		if err := putRef(bg, alice.Storage, name, genuine, ""); err != nil {
			t.Fatal(err)
		}
	}
	reqs, err := alice.ListJoinRequests(bg)
	if err != nil {
		t.Fatal(err)
	}
	if len(reqs) != 1 || reqs[0].DeviceID != mRes.DeviceID {
		t.Fatalf("forged requests listed: %+v", reqs)
	}
	if err := alice.ApproveMember(bg, vRes.DeviceID); !apperr.Is(err, apperr.CodeUntrusted) {
		t.Fatalf("approved a forged request: %v", err)
	}
}

func TestFakeSecretRejected(t *testing.T) {
	alice := newAlice(t)
	attacker := newDevice(t, alice)
	if _, err := attacker.InitializeRepository(bg); err != nil { // pending: has a key, not a principal
		t.Fatal(err)
	}
	recipients, _ := alice.ListRecipients(bg)
	forged, err := age.EncryptForPublicKeys(bundle.Marshal(map[string]string{"KEY": "evil"}), []string{recipients[0].PublicKey})
	if err != nil {
		t.Fatal(err)
	}
	_, version, err := getRef(bg, alice.Storage, secretsTag("default"))
	if err != nil {
		t.Fatal(err)
	}
	t.Run("raw ciphertext", func(t *testing.T) {
		if err := putRef(bg, alice.Storage, secretsTag("default"), forged, version); err != nil {
			t.Fatal(err)
		}
		if _, err := alice.ListSecrets(bg, "default"); !apperr.Is(err, apperr.CodeUntrusted) {
			t.Fatalf("unsigned ciphertext accepted: %v", err)
		}
	})
	t.Run("state signed by a non-principal", func(t *testing.T) {
		blob := signAsOutsider(t, alice, attacker, forged)
		_, version, _ := getRef(bg, alice.Storage, secretsTag("default"))
		if err := putRef(bg, alice.Storage, secretsTag("default"), blob, version); err != nil {
			t.Fatal(err)
		}
		if _, err := alice.ListSecrets(bg, "default"); !apperr.Is(err, apperr.CodeUntrusted) {
			t.Fatalf("outsider-signed state accepted: %v", err)
		}
		if err := alice.AddSecret(bg, "default", "X", "y"); !apperr.Is(err, apperr.CodeUntrusted) {
			t.Fatalf("write built on a forged state: %v", err)
		}
	})
}

// signAsOutsider builds a state with the attacker's own valid signature.
func signAsOutsider(t *testing.T, alice, attacker *App, ciphertext []byte) []byte {
	t.Helper()
	cfg, _ := attacker.loadProject()
	signer, err := attacker.Identities.LoadSigner(cfg.WorkspaceID)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = signer.Close() }()
	s, err := alice.openSession(bg)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ct, err := alice.Storage.Blobs.Put(bg, bytes.NewReader(ciphertext))
	if err != nil {
		t.Fatal(err)
	}
	blob, err := wsp.SignState(wsp.State{Workspace: cfg.WorkspaceID, Resource: secretsResource("default"), Sequence: 99, Previous: s.head.Digest,
		ControlGeneration: s.head.Generation, Control: s.head.Digest, Ciphertext: ct, Author: signer.Public().DeviceID()}, signer)
	if err != nil {
		t.Fatal(err)
	}
	return blob
}

func TestRemovedMemberCannotWrite(t *testing.T) {
	alice := newAlice(t)
	bob := approved(t, alice)
	// Bob keeps a copy of his own authority from before the removal.
	bobsView, err := bob.openSession(bg)
	if err != nil {
		t.Fatal(err)
	}
	defer bobsView.Close()
	bobsID := bobsView.self()
	if err := alice.RemoveMember(bg, string(bobsID)); err != nil {
		t.Fatal(err)
	}
	// Bob can no longer operate through the app.
	if err := bob.AddSecret(bg, "default", "LATE", "x"); !apperr.Is(err, apperr.CodeNotMember) {
		t.Fatalf("removed member wrote: %v", err)
	}
	// And a state he signs by hand is not accepted as current.
	ciphertext, _ := age.EncryptForPublicKeys(bundle.Marshal(map[string]string{"KEY": "bob"}), []string{mustRecipient(t, alice)})
	ct, _ := alice.Storage.Blobs.Put(bg, bytes.NewReader(ciphertext))
	_, version, _ := getRef(bg, alice.Storage, secretsTag("default"))
	cur, _ := alice.openSession(bg)
	defer cur.Close()
	blob, err := wsp.SignState(wsp.State{Workspace: cur.workspace, Resource: secretsResource("default"), Sequence: 99, Previous: cur.head.Digest,
		ControlGeneration: bobsView.head.Generation, Control: bobsView.head.Digest, Ciphertext: ct, Author: bobsID}, bobsView.signer)
	if err != nil {
		t.Fatal(err)
	}
	if err := putRef(bg, alice.Storage, secretsTag("default"), blob, version); err != nil {
		t.Fatal(err)
	}
	if _, err := alice.ListSecrets(bg, "default"); !apperr.Is(err, apperr.CodeUntrusted) {
		t.Fatalf("removed member's state accepted: %v", err)
	}
}

func mustRecipient(t *testing.T, a *App) string {
	t.Helper()
	r, err := a.ListRecipients(bg)
	if err != nil || len(r) == 0 {
		t.Fatal(err)
	}
	return r[0].PublicKey
}

func TestRemoveMemberReencryptsWithoutThem(t *testing.T) {
	alice := newAlice(t)
	bob := approved(t, alice)
	id := mustMember(t, alice, bob).DeviceID
	if err := alice.RemoveMember(bg, id); err != nil {
		t.Fatal(err)
	}
	s, err := alice.openSession(bg)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	read, err := s.readState(bg, secretsTag("default"), "default", true)
	if err != nil {
		t.Fatal(err)
	}
	if read.state.Sequence < 3 {
		t.Fatalf("state was not re-signed after removal: %+v", read.state)
	}
	if _, err := bob.ListSecrets(bg, "default"); !apperr.Is(err, apperr.CodeNotMember) {
		t.Fatalf("removed member still reads: %v", err)
	}
	if err := alice.RemoveMember(bg, id); !apperr.Is(err, apperr.CodeInvalidArgument) {
		t.Fatalf("removing twice: %v", err)
	}
}

func TestStateRollbackDetected(t *testing.T) {
	alice := newAlice(t)
	old, _, err := alice.Storage.Refs.Get(bg, secretsTag("default"))
	if err != nil {
		t.Fatal(err)
	}
	if err := alice.EditSecret(bg, "default", "KEY", "v2"); err != nil {
		t.Fatal(err)
	}
	if _, err := alice.ListSecrets(bg, "default"); err != nil { // accepts v2
		t.Fatal(err)
	}
	// Storage serves the previous, genuinely signed state again.
	_, version, _ := alice.Storage.Refs.Get(bg, secretsTag("default"))
	if err := alice.Storage.Refs.Put(bg, secretsTag("default"), old, version); err != nil {
		t.Fatal(err)
	}
	if _, err := alice.ListSecrets(bg, "default"); !apperr.Is(err, apperr.CodeRollback) {
		t.Fatalf("old state accepted: %v", err)
	}
	if err := alice.AddSecret(bg, "default", "N", "x"); !apperr.Is(err, apperr.CodeRollback) {
		t.Fatalf("write on top of a rolled-back state: %v", err)
	}
	// A device with no checkpoint cannot tell; that limitation is documented.
	fresh := newDevice(t, alice)
	fresh.Identities, fresh.CheckpointDir = alice.Identities, t.TempDir()
	if got, err := fresh.ListSecrets(bg, "default"); err != nil || got["KEY"] != "v1" {
		t.Fatalf("fresh client: %v %v", got, err)
	}
}

func TestControlRollbackDetected(t *testing.T) {
	alice := newAlice(t)
	cfg, _ := alice.loadProject()
	genesis, _, err := alice.Storage.Refs.Get(bg, wsp.ControlRef)
	if err != nil {
		t.Fatal(err)
	}
	if string(genesis) != cfg.ControlGenesis {
		t.Fatalf("genesis %s != head %s", cfg.ControlGenesis, genesis)
	}
	bob := newDevice(t, alice)
	res, _ := bob.InitializeRepository(bg)
	if err := alice.ApproveMember(bg, res.DeviceID); err != nil {
		t.Fatal(err)
	}
	// Storage hides the approval by serving the genesis head again.
	_, version, _ := alice.Storage.Refs.Get(bg, wsp.ControlRef)
	if err := alice.Storage.Refs.Put(bg, wsp.ControlRef, genesis, version); err != nil {
		t.Fatal(err)
	}
	if _, err := alice.ListSecrets(bg, "default"); !apperr.Is(err, apperr.CodeRollback) {
		t.Fatalf("old control accepted: %v", err)
	}
	if _, err := alice.ListMembers(bg); !apperr.Is(err, apperr.CodeRollback) {
		t.Fatalf("old control listed: %v", err)
	}
}

func TestForgedControlRejected(t *testing.T) {
	alice := newAlice(t)
	mallory := newDevice(t, alice)
	if _, err := mallory.InitializeRepository(bg); err != nil {
		t.Fatal(err)
	}
	ms, _ := mallory.Identities.LoadSigner(mustWorkspace(t, mallory))
	defer func() { _ = ms.Close() }()
	s, _ := alice.openSession(bg)
	defer s.Close()
	self := wsp.Principal{ID: ms.Public().DeviceID(), Signing: ms.Public(), Recipient: mustRecipient(t, alice), Admin: true}
	forged, err := wsp.SignControl(wsp.Control{Workspace: s.workspace, Generation: 1, Previous: s.head.Digest, Author: self.ID,
		Principals: append(append([]wsp.Principal{}, s.head.Principals...), self)}, ms)
	if err != nil {
		t.Fatal(err)
	}
	_, version, _ := alice.Storage.Refs.Get(bg, wsp.ControlRef)
	if err := putRef(bg, alice.Storage, wsp.ControlRef, forged, version); err != nil {
		t.Fatal(err)
	}
	if _, err := alice.ListMembers(bg); !apperr.Is(err, apperr.CodeUntrusted) {
		t.Fatalf("forged control accepted: %v", err)
	}
}

func mustWorkspace(t *testing.T, a *App) string {
	t.Helper()
	id, err := a.WorkspaceID()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func TestBootstrapRequiresTrustedGenesis(t *testing.T) {
	alice := newAlice(t)
	bob := newDevice(t, alice)
	cfg, _ := bob.loadProject()
	cfg.ControlGenesis = ""
	if err := config.SaveProjectTo(bob.RepositoryDir, cfg); err != nil {
		t.Fatal(err)
	}
	// WorkspaceID alone is not enough to join.
	if _, err := bob.InitializeRepository(bg); !apperr.Is(err, apperr.CodeInvalidArgument) {
		t.Fatalf("joined without a genesis: %v", err)
	}
	// A wrong genesis fails verification instead of being trusted.
	cfg.ControlGenesis = "sha256:" + string(bytes.Repeat([]byte("0"), 64))
	if err := config.SaveProjectTo(bob.RepositoryDir, cfg); err != nil {
		t.Fatal(err)
	}
	if _, err := bob.InitializeRepository(bg); !apperr.Is(err, apperr.CodeUntrusted) {
		t.Fatalf("joined with a wrong genesis: %v", err)
	}
}

func TestIncompatibleStorageRejected(t *testing.T) {
	t.Run("secrets without control", func(t *testing.T) {
		a := &App{Storage: newMemRegistry(), Identities: newMemKeyStore(), CheckpointDir: t.TempDir()}
		prepareApp(t, a, "default")
		if err := putRef(bg, a.Storage, secretsTag("default"), []byte("legacy"), ""); err != nil {
			t.Fatal(err)
		}
		if _, err := a.InitializeRepository(bg); !apperr.Is(err, apperr.CodeIncompatibleStorage) {
			t.Fatalf("legacy storage accepted: %v", err)
		}
	})
	t.Run("genesis expected but storage empty", func(t *testing.T) {
		alice := newAlice(t)
		other := &App{Storage: newMemRegistry(), Identities: newMemKeyStore(), CheckpointDir: t.TempDir(), RepositoryDir: alice.RepositoryDir}
		if err := putRef(bg, other.Storage, workspaceKey, []byte(testWorkspaceID), ""); err != nil {
			t.Fatal(err)
		}
		if _, err := other.InitializeRepository(bg); !apperr.Is(err, apperr.CodeIncompatibleStorage) {
			t.Fatalf("trust root silently replaced: %v", err)
		}
	})
}

func TestSigningKeyIsNotStoredInWorkspaceStorage(t *testing.T) {
	alice := newAlice(t)
	ws := mustWorkspace(t, alice)
	signer, err := alice.Identities.LoadSigner(ws)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = signer.Close() }()
	if alice.selfDevice(ws) != signer.Public().DeviceID() {
		t.Fatal("device id mismatch")
	}
	// Storage holds only public material: the control lists the public key and
	// the age recipient, and neither equals the other key's material.
	s, _ := alice.openSession(bg)
	defer s.Close()
	p, _ := s.head.Principal(signer.Public().DeviceID())
	if p.Recipient == string(p.Signing.Bytes) {
		t.Fatal("encryption and signing keys are the same")
	}
}

func TestLastAdminCannotBeRemovedOrDemoted(t *testing.T) {
	alice := newAlice(t)
	id := mustMember(t, alice, alice).DeviceID
	if err := alice.SetAdmin(bg, id, false); !apperr.Is(err, apperr.CodeInvalidArgument) {
		t.Fatalf("demoting the last admin: %v", err)
	}
	if err := alice.RemoveMember(bg, id); !apperr.Is(err, apperr.CodeInvalidArgument) {
		t.Fatalf("removing the last admin: %v", err)
	}
	if members, err := alice.ListMembers(bg); err != nil || len(members) != 1 || !members[0].Admin {
		t.Fatalf("members changed: %+v %v", members, err)
	}
}
