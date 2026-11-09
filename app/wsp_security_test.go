package app

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/enbu-net/enbu/app/apptest"
	"github.com/enbu-net/enbu/pkg/age"
	"github.com/enbu-net/enbu/pkg/apperr"
	"github.com/enbu-net/enbu/pkg/config"
	"github.com/enbu-net/enbu/pkg/storage"
	storagetest "github.com/enbu-net/enbu/pkg/storage/storagetest"
	"github.com/enbu-net/enbu/pkg/wsp"
	digest "github.com/opencontainers/go-digest"
)

func TestJoinApproveAndShareSecrets(t *testing.T) {
	alice := newAlice(t)
	bob := newDevice(t, alice)
	res, err := bob.InitializeRepository(bg, InitOptions{})
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
	// An unknown environment needs only the local enbu.toml, so it is reported
	// before membership is checked.
	if _, err := bob.ListSecrets(bg, "missing"); !apperr.Is(err, apperr.CodeEnvironmentMissing) {
		t.Fatalf("pending device read an unknown environment: %v", err)
	}
	if err := bob.AddSecret(bg, "missing", "BOB", "x"); !apperr.Is(err, apperr.CodeEnvironmentMissing) {
		t.Fatalf("pending device wrote an unknown environment: %v", err)
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

// Storage write access alone must not make anyone a recipient: only the signed
// Control lists them, so objects planted in storage change nothing.
func TestRecipientInjection(t *testing.T) {
	alice := newAlice(t)
	attacker := mustKeyPair(t)
	ws := mustWorkspace(t, alice)
	// Junk in the request namespace, and a Control nobody with authority signed.
	for _, junk := range [][]byte{[]byte(attacker.PublicKey), []byte("recipient-0000")} {
		if _, err := wsp.PublishJoinRequest(bg, alice.Storage, junk); err != nil {
			t.Fatal(err)
		}
	}
	mallory := newDevice(t, alice)
	requestJoin(t, mallory)
	ms, _ := loadSigner(mallory, ws)
	defer func() { _ = ms.Close() }()
	s, err := alice.openSession(bg)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	self := wsp.Principal{ID: ms.Public().DeviceID(), Signing: ms.Public(), Recipient: attacker.PublicKey, Admin: true}
	forged, err := wsp.SignControl(wsp.Control{Workspace: ws, Parents: []digest.Digest{s.head.Digest}, Height: s.head.Height + 1, Author: self.ID,
		Principals: append(append([]wsp.Principal{}, s.head.Principals...), self)}, ms)
	if err != nil {
		t.Fatal(err)
	}
	if err := alice.Storage.Publish(bg, storage.Object{Kind: storage.KindControl, Rev: digest.FromBytes(forged), Head: forged}); err != nil {
		t.Fatal(err)
	}

	if err := alice.AddSecret(bg, "default", "NEW", "secret"); err != nil {
		t.Fatal(err)
	}
	members, err := alice.ListMembers(bg)
	if err != nil || len(members) != 1 || members[0].Recipient == attacker.PublicKey {
		t.Fatalf("members: %+v %v", members, err)
	}
	// The ciphertext alice just wrote cannot be opened with the attacker's key.
	read, err := s.readResource(bg, s.resource("default"), nil, true)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, err := storage.ReadPayload(bg, alice.Storage, storage.KindState, read.heads[0].Scope(), read.heads[0].Digest, storage.MaxPayloadBytes)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := age.Decrypt(ciphertext, attacker.Identity); err == nil {
		t.Fatal("injected recipient can decrypt")
	}
}

// A fake secret is a state somebody else made up. Without a member's signature
// it is skipped, and it does not stop the real secrets from being read or written.
func TestFakeSecretRejected(t *testing.T) {
	alice := newAlice(t)
	attacker := newDevice(t, alice)
	requestJoin(t, attacker)
	members, _ := alice.ListMembers(bg)
	forged, err := age.EncryptForPublicKeys(encodeSecrets(map[string]string{"KEY": "evil"}), []string{members[0].Recipient})
	if err != nil {
		t.Fatal(err)
	}
	s, err := alice.openSession(bg)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ws := mustWorkspace(t, alice)
	resource := s.resource("default")
	t.Run("unsigned state", func(t *testing.T) {
		junk := []byte("not a signed state")
		if err := alice.Storage.Publish(bg, storage.Object{Kind: storage.KindState, Scope: storage.StateScope(ws, resource), Rev: digest.FromBytes(junk), Head: junk, Payload: forged}); err != nil {
			t.Fatal(err)
		}
		if got, err := alice.ListSecrets(bg, "default"); err != nil || got["KEY"] != "v1" {
			t.Fatalf("unsigned state changed the secrets: %v %v", got, err)
		}
	})
	t.Run("state signed by a non-principal", func(t *testing.T) {
		publishRevision(t, alice.Storage, attacker, ws, resource, s.head.Digest, forged, revisionsOf(t, alice, "default")[0])
		if got, err := alice.ListSecrets(bg, "default"); err != nil || got["KEY"] != "v1" {
			t.Fatalf("outsider-signed state changed the secrets: %v %v", got, err)
		}
		if err := alice.AddSecret(bg, "default", "X", "y"); err != nil {
			t.Fatalf("write beside a forged state: %v", err)
		}
		if got, err := alice.ListSecrets(bg, "default"); err != nil || got["KEY"] != "v1" || got["X"] != "y" {
			t.Fatalf("secrets: %v %v", got, err)
		}
	})
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
	// And a revision he signs by hand, claiming the control he knew, is set
	// aside: it is not accepted as current and does not change what is read.
	ciphertext, _ := age.EncryptForPublicKeys(encodeSecrets(map[string]string{"KEY": "bob"}), []string{mustRecipient(t, alice)})
	cur, _ := alice.openSession(bg)
	defer cur.Close()
	sv, err := cur.loadResource(bg, cur.resource("default"))
	if err != nil {
		t.Fatal(err)
	}
	publishRevision(t, alice.Storage, bob, cur.workspace, cur.resource("default"), bobsView.head.Digest, ciphertext, sv.Heads[0].Digest)
	got, err := alice.ListSecrets(bg, "default")
	if err != nil || got["KEY"] != "v1" {
		t.Fatalf("removed member's revision changed the secrets: %v %v", got, err)
	}
	// Alice writes on top of what she trusts, and keeps working.
	if err := alice.AddSecret(bg, "default", "AFTER", "ok"); err != nil {
		t.Fatal(err)
	}
	// Re-admitting the same signing key must not revive the old-control
	// forgery that all remaining members already set aside.
	if _, err := bob.InitializeRepository(bg, InitOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := alice.ApproveMember(bg, string(bobsID)); err != nil {
		t.Fatal(err)
	}
	got, err = alice.ListSecrets(bg, "default")
	if err != nil || got["KEY"] != "v1" || got["AFTER"] != "ok" {
		t.Fatalf("readmission revived stale content: %v %v", got, err)
	}
	if err := bob.AddSecret(bg, "default", "READMITTED", "fresh"); err != nil {
		t.Fatalf("fresh write after readmission: %v", err)
	}
}

func TestRemoveMemberReencryptsWithoutThem(t *testing.T) {
	alice := newAlice(t)
	bob := approved(t, alice)
	id := mustMember(t, alice, bob).DeviceID
	before, err := alice.openSession(bg)
	if err != nil {
		t.Fatal(err)
	}
	oldRead, err := before.readResource(bg, before.resource("default"), nil, true)
	before.Close()
	if err != nil {
		t.Fatal(err)
	}
	if err := alice.RemoveMember(bg, id); err != nil {
		t.Fatal(err)
	}
	s, err := alice.openSession(bg)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	read, err := s.readResource(bg, s.resource("default"), nil, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(read.heads) != 1 || read.heads[0].Op != wsp.OpSync || read.heads[0].Digest == oldRead.heads[0].Digest || readableBy(t, s, bob, read.heads[0]) {
		t.Fatalf("state was not re-encrypted without bob: %+v", read.heads)
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
	oldRevs := revisionsOf(t, alice, "default")
	if err := alice.EditSecret(bg, "default", "KEY", "v2"); err != nil {
		t.Fatal(err)
	}
	if _, err := alice.ListSecrets(bg, "default"); err != nil { // accepts v2
		t.Fatal(err)
	}
	var newest digest.Digest
	for _, r := range revisionsOf(t, alice, "default") {
		if r != oldRevs[0] {
			newest = r
		}
	}
	// Storage serves the previous, genuinely signed state again.
	real := alice.Storage
	alice.Storage = hide(real, newest)
	if _, err := alice.ListSecrets(bg, "default"); !apperr.Is(err, apperr.CodeRollback) {
		t.Fatalf("old state accepted: %v", err)
	}
	if err := alice.AddSecret(bg, "default", "N", "x"); !apperr.Is(err, apperr.CodeRollback) {
		t.Fatalf("write on top of a rolled-back state: %v", err)
	}
	// A device with no checkpoint cannot tell; that limitation is documented.
	fresh := newDevice(t, alice)
	fresh.Identities, fresh.CheckpointDir, fresh.Storage = alice.Identities, t.TempDir(), alice.Storage
	if got, err := fresh.ListSecrets(bg, "default"); err != nil || got["KEY"] != "v1" {
		t.Fatalf("fresh client: %v %v", got, err)
	}
}

func TestControlRollbackDetected(t *testing.T) {
	alice := newAlice(t)
	bob := newDevice(t, alice)
	res := requestJoin(t, bob)
	if err := alice.ApproveMember(bg, res.DeviceID); err != nil {
		t.Fatal(err)
	}
	cur, err := alice.openControl(bg)
	if err != nil {
		t.Fatal(err)
	}
	// Storage hides the approval.
	real := alice.Storage
	alice.Storage = hide(real, cur.head.Digest)
	if _, err := alice.ListSecrets(bg, "default"); !apperr.Is(err, apperr.CodeRollback) {
		t.Fatalf("old control accepted: %v", err)
	}
	if _, err := alice.ListMembers(bg); !apperr.Is(err, apperr.CodeRollback) {
		t.Fatalf("old control listed: %v", err)
	}
}

func TestBootstrapRequiresTrustedGenesis(t *testing.T) {
	alice := newAlice(t)
	bob := newDevice(t, alice)
	cfg, _ := bob.loadProject()
	cfg.ControlGenesis = ""
	if err := config.SaveProjectTo(bob.RepositoryDir, cfg); err != nil {
		t.Fatal(err)
	}
	// WorkspaceID alone is not enough to join, and a workspace that is already
	// there is never adopted on faith.
	if _, err := bob.InitializeRepository(bg, InitOptions{}); !apperr.Is(err, apperr.CodeIncompatibleStorage) {
		t.Fatalf("joined without a genesis: %v", err)
	}
	// A genesis storage does not hold is not trusted.
	cfg.ControlGenesis = "sha256:" + string(bytes.Repeat([]byte("0"), 64))
	if err := config.SaveProjectTo(bob.RepositoryDir, cfg); err != nil {
		t.Fatal(err)
	}
	if _, err := bob.InitializeRepository(bg, InitOptions{}); !apperr.Is(err, apperr.CodeIncompatibleStorage) {
		t.Fatalf("joined with a wrong genesis: %v", err)
	}
}

func TestIncompatibleStorageRejected(t *testing.T) {
	t.Run("storage already holds a workspace", func(t *testing.T) {
		alice := newAlice(t)
		other := &App{Storage: alice.Storage, Identities: &apptest.Identities{}, CheckpointDir: t.TempDir()}
		prepareApp(t, other, "default")
		if _, err := other.InitializeRepository(bg, InitOptions{}); !apperr.Is(err, apperr.CodeIncompatibleStorage) {
			t.Fatalf("a workspace without a trusted genesis was adopted: %v", err)
		}
	})
	t.Run("genesis expected but storage empty", func(t *testing.T) {
		alice := newAlice(t)
		other := &App{Storage: newMemRegistry(), Identities: &apptest.Identities{}, CheckpointDir: t.TempDir(), RepositoryDir: alice.RepositoryDir}
		if _, err := other.InitializeRepository(bg, InitOptions{}); !apperr.Is(err, apperr.CodeIncompatibleStorage) {
			t.Fatalf("trust root silently replaced: %v", err)
		}
	})
}

func TestSigningKeyIsNotStoredInWorkspaceStorage(t *testing.T) {
	alice := newAlice(t)
	ws := mustWorkspace(t, alice)
	signer, err := loadSigner(alice, ws)
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

// foundingApp is a first device on empty storage whose publication of the
// genesis control goes through publish, so a test can watch or fail the moment.
func foundingApp(t *testing.T, publish func(ctx context.Context, data []byte) error) *App {
	t.Helper()
	a := &App{Identities: &apptest.Identities{}, CheckpointDir: t.TempDir()}
	a.Storage = storagetest.Wrap(newMemRegistry(), storagetest.Hooks{
		Publish: func(ctx context.Context, next storage.Store, o storage.Object) error {
			if o.Kind == storage.KindControl && publish != nil {
				if err := publish(ctx, o.Head); err != nil {
					return err
				}
			}
			return next.Publish(ctx, o)
		},
	})
	prepareApp(t, a, "default")
	return a
}

func genesisInConfig(t *testing.T, a *App) string {
	t.Helper()
	cfg, err := a.loadProject()
	if err != nil {
		t.Fatal(err)
	}
	return cfg.ControlGenesis
}

// A publish whose reply was lost has stored the genesis although init failed.
// The retry recognises the genesis by this device's signature and adopts it
// instead of refusing the storage or founding a second workspace.
func TestLostPublishReplyAdoptsTheOwnGenesisOnRetry(t *testing.T) {
	lose := true
	a := &App{Identities: &apptest.Identities{}, CheckpointDir: t.TempDir()}
	a.Storage = storagetest.Wrap(newMemRegistry(), storagetest.Hooks{
		Publish: func(ctx context.Context, next storage.Store, o storage.Object) error {
			if err := next.Publish(ctx, o); err != nil {
				return err
			}
			if o.Kind == storage.KindControl && lose {
				return errors.New("connection reset after the upload")
			}
			return nil
		},
	})
	prepareApp(t, a, "default")
	if _, err := a.InitializeRepository(bg, InitOptions{}); err == nil {
		t.Fatal("init succeeded although the publish reply was lost")
	}
	revs, err := a.Storage.Discover(bg, storage.KindControl, "")
	if err != nil || len(revs) != 1 {
		t.Fatalf("published controls: %v %v", revs, err)
	}
	if g := genesisInConfig(t, a); g != "" {
		t.Fatalf("enbu.toml names %s before the publish was confirmed", g)
	}
	lose = false
	result, err := a.InitializeRepository(bg, InitOptions{})
	if err != nil {
		t.Fatalf("retry: %v", err)
	}
	if !result.Founded || result.ControlGenesis != string(revs[0]) || genesisInConfig(t, a) != string(revs[0]) {
		t.Fatalf("retry did not adopt the published genesis %s: %+v", revs[0], result)
	}
	if after, err := a.Storage.Discover(bg, storage.KindControl, ""); err != nil || len(after) != 1 {
		t.Fatalf("retry published another genesis: %v %v", after, err)
	}
}

// A publish that failed stored nothing, so the retry simply founds again.
func TestFailedPublishFoundsAgainOnRetry(t *testing.T) {
	fail := true
	a := foundingApp(t, func(context.Context, []byte) error {
		if fail {
			return errors.New("storage unavailable")
		}
		return nil
	})
	if _, err := a.InitializeRepository(bg, InitOptions{}); err == nil {
		t.Fatal("init succeeded although the control could not be published")
	}
	if g := genesisInConfig(t, a); g != "" {
		t.Fatalf("enbu.toml names %s although nothing was published", g)
	}
	fail = false
	result, err := a.InitializeRepository(bg, InitOptions{})
	if err != nil {
		t.Fatalf("retry: %v", err)
	}
	if !result.Founded || genesisInConfig(t, a) != result.ControlGenesis {
		t.Fatalf("the retry did not found the workspace: %+v", result)
	}
}

// Another device's genesis of the same workspace ID in storage is not this
// device's lost founding, so founding refuses the storage.
func TestFoundingRefusesAnotherDevicesGenesis(t *testing.T) {
	alice := newAlice(t)
	bob := newDevice(t, alice)
	setGenesis(t, bob, "")
	before, err := bob.Storage.Discover(bg, storage.KindControl, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bob.InitializeRepository(bg, InitOptions{}); !apperr.Is(err, apperr.CodeIncompatibleStorage) {
		t.Fatalf("founded over another device's genesis: %v", err)
	}
	if after, err := bob.Storage.Discover(bg, storage.KindControl, ""); err != nil || len(after) != len(before) {
		t.Fatalf("a genesis was published: %v %v", after, err)
	}
	if g := genesisOf(t, bob); g != "" {
		t.Fatalf("enbu.toml records %s", g)
	}
}

// A device with no pin for the genesis enbu.toml names, signed by someone
// else, has not founded it: its repository pin must not move to it.
func TestAnotherDevicesConfiguredGenesisIsNotAdopted(t *testing.T) {
	alice := newAlice(t)
	shared := alice.Storage
	bob := newDevice(t, alice)
	cfg, err := bob.loadProject()
	if err != nil {
		t.Fatal(err)
	}
	own := cfg
	own.WorkspaceID = "44444444-4444-4444-8444-444444444444"
	own.ControlGenesis = ""
	if err := config.SaveProjectTo(bob.RepositoryDir, own); err != nil {
		t.Fatal(err)
	}
	bob.Storage = newMemRegistry()
	if _, err := bob.InitializeRepository(bg, InitOptions{}); err != nil {
		t.Fatalf("bob founding his own workspace: %v", err)
	}
	before, err := bob.trust().Repository(bob.repositoryKey())
	if err != nil || before.Workspace != own.WorkspaceID {
		t.Fatalf("repository pin: %+v %v", before, err)
	}

	bob.Storage = shared
	if err := config.SaveProjectTo(bob.RepositoryDir, cfg); err != nil {
		t.Fatal(err)
	}
	if _, err := bob.InitializeRepository(bg, InitOptions{}); !apperr.Is(err, apperr.CodeTrustRootChanged) {
		t.Fatalf("alice's genesis treated as bob's founding: %v", err)
	}
	if after, err := bob.trust().Repository(bob.repositoryKey()); err != nil || after != before {
		t.Fatalf("the repository pin moved: %+v %v", after, err)
	}
}

// A storage failure while looking for this device's own genesis is returned,
// even when the next read would succeed, and pins nothing.
func TestConfiguredGenesisLookupFailureIsReturned(t *testing.T) {
	alice := newAlice(t)
	bob := newDevice(t, alice)
	failed := false
	bob.Storage = storagetest.Wrap(alice.Storage, storagetest.Hooks{
		FetchHead: func(ctx context.Context, next storage.Store, kind storage.Kind, scope string, rev digest.Digest) ([]byte, error) {
			if !failed {
				failed = true
				return nil, storage.ErrCorrupt
			}
			return next.FetchHead(ctx, kind, scope, rev)
		},
	})
	if _, err := bob.InitializeRepository(bg, InitOptions{}); !apperr.Is(err, apperr.CodeUntrusted) {
		t.Fatalf("lookup failure: %v", err)
	}
	if pinned, err := bob.trust().Pinned(mustWorkspace(t, bob)); err != nil || pinned != (wsp.Root{}) {
		t.Fatalf("pinned after a failed lookup: %+v %v", pinned, err)
	}
}

// History written by a member who has since been removed is still history.
func TestHistoryByARemovedMemberCanBeDiffedAndRestored(t *testing.T) {
	alice := newAlice(t)
	bob := approved(t, alice)
	if err := bob.AddSecret(bg, "default", "BOB", "from bob"); err != nil {
		t.Fatal(err)
	}
	if err := alice.RemoveMember(bg, mustMember(t, alice, bob).DeviceID); err != nil {
		t.Fatal(err)
	}
	entries, err := alice.ListHistory(bg, "default")
	if err != nil || len(entries) < 2 {
		t.Fatalf("history: %+v %v", entries, err)
	}
	// The newest entry is bob's write; the re-encryption after the removal repeats it.
	diff, err := alice.DiffHistory(bg, "default", len(entries)-1, len(entries))
	if err != nil {
		t.Fatalf("diff across a removed member's revision: %v", err)
	}
	if len(diff.Added) != 1 || diff.Added[0] != "BOB" {
		t.Fatalf("diff = %+v", diff)
	}
	if err := alice.RestoreHistory(bg, "default", len(entries)); err != nil {
		t.Fatalf("restore a removed member's revision: %v", err)
	}
	got, err := alice.ListSecrets(bg, "default")
	if err != nil || got["BOB"] != "from bob" {
		t.Fatalf("restored secrets: %v %v", got, err)
	}
	// The removed member cannot read anything any more.
	if _, err := bob.ListSecrets(bg, "default"); !apperr.Is(err, apperr.CodeNotMember) {
		t.Fatalf("removed member: %v", err)
	}
}

// If an admin changes the members while a write is in flight, the write must
// restart on the new list instead of encrypting for the old one.
func TestWriteRestartsWhenTheMembersChangeMidway(t *testing.T) {
	alice := newAlice(t)
	base := alice.Storage
	extra := extraPrincipal(t)
	moved := false
	alice.Storage = storagetest.Wrap(base, storagetest.Hooks{
		Discover: func(ctx context.Context, next storage.Store, kind storage.Kind, scope string) ([]digest.Digest, error) {
			if kind == storage.KindState && !moved {
				moved = true
				s, err := (&App{Storage: base, Identities: alice.Identities, CheckpointDir: t.TempDir(), RepositoryDir: alice.RepositoryDir}).openSession(ctx)
				if err != nil {
					t.Error(err)
				} else {
					defer s.Close()
					if _, err := wsp.UpdateControl(ctx, base, s.view, s.signer, func(c *wsp.Control) error {
						c.Principals = append(c.Principals, extra)
						return nil
					}); err != nil {
						t.Error(err)
					}
				}
			}
			return next.Discover(ctx, kind, scope)
		},
	})
	if err := alice.AddSecret(bg, "default", "NEW", "value"); err != nil {
		t.Fatal(err)
	}
	s, err := alice.openSession(bg)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	read, err := s.readResource(bg, s.resource("default"), nil, true)
	if err != nil {
		t.Fatal(err)
	}
	if !moved || s.head.Height != 1 || read.heads[0].Control != s.head.Digest {
		t.Fatalf("moved=%v head=%d state written under %s: it still used the old member list", moved, s.head.Height, read.heads[0].Control)
	}
}

func TestFoundingNewWorkspaceRetriesAfterVerificationDisconnect(t *testing.T) {
	a := newAlice(t)
	cfg := config.NewProjectWithEnvironment("default")
	if err := config.SaveProjectTo(a.RepositoryDir, cfg); err != nil {
		t.Fatal(err)
	}
	published, offline := false, true
	a.Storage = storagetest.Wrap(storagetest.NewMemory(), storagetest.Hooks{
		Publish: func(ctx context.Context, next storage.Store, o storage.Object) error {
			if err := next.Publish(ctx, o); err != nil {
				return err
			}
			if o.Kind == storage.KindControl {
				published = true
			}
			return nil
		},
		Discover: func(ctx context.Context, next storage.Store, k storage.Kind, scope string) ([]digest.Digest, error) {
			if published && offline {
				return nil, errors.New("disconnected during verification")
			}
			return next.Discover(ctx, k, scope)
		},
	})
	if _, err := a.InitializeRepository(bg, InitOptions{}); err == nil {
		t.Fatal("verification unexpectedly succeeded")
	}
	genesis := genesisInConfig(t, a)
	if genesis == "" {
		t.Fatal("the published genesis was not recorded")
	}
	offline = false
	result, err := a.InitializeRepository(bg, InitOptions{})
	if err != nil {
		t.Fatalf("retry new workspace in pinned checkout: %v", err)
	}
	if result.ControlGenesis != genesis || result.WorkspaceID != cfg.WorkspaceID {
		t.Fatal("retry changed workspace or root")
	}
}
