package app

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/enbu-net/enbu/pkg/age"
	"github.com/enbu-net/enbu/pkg/apperr"
	"github.com/enbu-net/enbu/pkg/bundle"
	"github.com/enbu-net/enbu/pkg/config"
	"github.com/enbu-net/enbu/pkg/storage"
	storagetest "github.com/enbu-net/enbu/pkg/storage/storagetest"
	"github.com/enbu-net/enbu/pkg/wsp"
	digest "github.com/opencontainers/go-digest"
)

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
	ms, _ := mallory.Identities.LoadSigner(ws)
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
	if err := alice.Storage.Publish(bg, storage.Object{Kind: storage.KindControl, Rev: digest.FromBytes(forged), Signed: forged}); err != nil {
		t.Fatal(err)
	}

	if err := alice.AddSecret(bg, "default", "NEW", "secret"); err != nil {
		t.Fatal(err)
	}
	recipients, err := alice.ListRecipients(bg)
	if err != nil || len(recipients) != 1 || recipients[0].PublicKey == attacker.PublicKey {
		t.Fatalf("recipients: %+v %v", recipients, err)
	}
	// The ciphertext alice just wrote cannot be opened with the attacker's key.
	read, err := s.readResource(bg, "default", nil, true)
	if err != nil {
		t.Fatal(err)
	}
	o, err := alice.Storage.Fetch(bg, storage.KindState, read.heads[0].Scope(), read.heads[0].Digest)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := age.Decrypt(o.Cipher, attacker.Identity); err == nil {
		t.Fatal("injected recipient can decrypt")
	}
}

// A fake secret is a state somebody else made up. Without a member's signature
// it is skipped, and it does not stop the real secrets from being read or written.
func TestFakeSecretRejected(t *testing.T) {
	alice := newAlice(t)
	attacker := newDevice(t, alice)
	requestJoin(t, attacker)
	recipients, _ := alice.ListRecipients(bg)
	forged, err := age.EncryptForPublicKeys(bundle.Marshal(map[string]string{"KEY": "evil"}), []string{recipients[0].PublicKey})
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
		if err := alice.Storage.Publish(bg, storage.Object{Kind: storage.KindState, Scope: storage.StateScope(ws, resource), Rev: digest.FromBytes(junk), Signed: junk, Cipher: forged}); err != nil {
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
	ciphertext, _ := age.EncryptForPublicKeys(bundle.Marshal(map[string]string{"KEY": "bob"}), []string{mustRecipient(t, alice)})
	cur, _ := alice.openSession(bg)
	defer cur.Close()
	sv, err := cur.loadResource(bg, "default")
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
}

func TestRemoveMemberReencryptsWithoutThem(t *testing.T) {
	alice := newAlice(t)
	bob := approved(t, alice)
	id := mustMember(t, alice, bob).DeviceID
	before, err := alice.openSession(bg)
	if err != nil {
		t.Fatal(err)
	}
	oldRead, err := before.readResource(bg, "default", nil, true)
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
	read, err := s.readResource(bg, "default", nil, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(read.heads) != 1 || read.heads[0].Control != s.head.Digest || read.heads[0].Digest == oldRead.heads[0].Digest {
		t.Fatalf("state was not re-signed after removal: %+v", read.heads)
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
	if _, err := bob.InitializeRepository(bg); !apperr.Is(err, apperr.CodeIncompatibleStorage) {
		t.Fatalf("joined without a genesis: %v", err)
	}
	// A genesis storage does not hold is not trusted.
	cfg.ControlGenesis = "sha256:" + string(bytes.Repeat([]byte("0"), 64))
	if err := config.SaveProjectTo(bob.RepositoryDir, cfg); err != nil {
		t.Fatal(err)
	}
	if _, err := bob.InitializeRepository(bg); !apperr.Is(err, apperr.CodeIncompatibleStorage) {
		t.Fatalf("joined with a wrong genesis: %v", err)
	}
}

func TestIncompatibleStorageRejected(t *testing.T) {
	t.Run("storage already holds a workspace", func(t *testing.T) {
		alice := newAlice(t)
		other := &App{Storage: alice.Storage, Identities: newMemKeyStore(), CheckpointDir: t.TempDir()}
		prepareApp(t, other, "default")
		if _, err := other.InitializeRepository(bg); !apperr.Is(err, apperr.CodeIncompatibleStorage) {
			t.Fatalf("a workspace without a trusted genesis was adopted: %v", err)
		}
	})
	t.Run("genesis expected but storage empty", func(t *testing.T) {
		alice := newAlice(t)
		other := &App{Storage: newMemRegistry(), Identities: newMemKeyStore(), CheckpointDir: t.TempDir(), RepositoryDir: alice.RepositoryDir}
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

// foundingApp is a first device on empty storage whose publication of the
// genesis control goes through publish, so a test can watch or fail the moment.
func foundingApp(t *testing.T, publish func(ctx context.Context, data []byte) error) *App {
	t.Helper()
	a := &App{Identities: newMemKeyStore(), CheckpointDir: t.TempDir()}
	a.Storage = storagetest.Wrap(newMemRegistry(), storagetest.Hooks{
		Publish: func(ctx context.Context, next storage.Store, o storage.Object) error {
			if o.Kind == storage.KindControl && publish != nil {
				if err := publish(ctx, o.Signed); err != nil {
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

// If enbu.toml cannot be written after the control is public, the founder is
// locked out of their own workspace. So the digest is recorded first.
func TestFounderRecordsTheGenesisBeforePublishingIt(t *testing.T) {
	var recordedWhenPublished string
	var a *App
	a = foundingApp(t, func(_ context.Context, data []byte) error {
		recordedWhenPublished = genesisInConfig(t, a)
		if recordedWhenPublished != string(digest.FromBytes(data)) {
			t.Errorf("control_genesis was %q when the control was published, want its digest", recordedWhenPublished)
		}
		return nil
	})
	if _, err := a.InitializeRepository(bg); err != nil {
		t.Fatal(err)
	}
	if recordedWhenPublished == "" || genesisInConfig(t, a) != recordedWhenPublished {
		t.Fatalf("recorded %q, final %q", recordedWhenPublished, genesisInConfig(t, a))
	}
}

func TestFailedPublishLeavesNoGenesisBehind(t *testing.T) {
	fail := true
	a := foundingApp(t, func(context.Context, []byte) error {
		if fail {
			return errors.New("storage unavailable")
		}
		return nil
	})
	if _, err := a.InitializeRepository(bg); err == nil {
		t.Fatal("init succeeded although the control could not be published")
	}
	if g := genesisInConfig(t, a); g != "" {
		t.Fatalf("control_genesis %q was left for a control that does not exist", g)
	}
	fail = false
	if _, err := a.InitializeRepository(bg); err != nil {
		t.Fatalf("retry: %v", err)
	}
	if genesisInConfig(t, a) == "" {
		t.Fatal("the retry did not record a genesis")
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
	read, err := s.readResource(bg, "default", nil, true)
	if err != nil {
		t.Fatal(err)
	}
	if !moved || s.head.Height != 1 || read.heads[0].Control != s.head.Digest {
		t.Fatalf("moved=%v head=%d state written under %s: it still used the old member list", moved, s.head.Height, read.heads[0].Control)
	}
}
