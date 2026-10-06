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

func TestFakeSecretRejected(t *testing.T) {
	alice := newAlice(t)
	attacker := newDevice(t, alice)
	requestJoin(t, attacker)
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
		blob := signAsOutsider(t, alice, attacker, "default", forged)
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
	res := requestJoin(t, bob)
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

// foundingApp is a first device on empty storage whose writes of the control
// head go through put, so a test can watch or fail the moment of publication.
func foundingApp(t *testing.T, put func(ctx context.Context, data []byte) error) *App {
	t.Helper()
	base := newMemRegistry()
	a := &App{Identities: newMemKeyStore(), CheckpointDir: t.TempDir()}
	a.Storage = storagetest.Wrap(base, &hookedStorage{Objects: storagetest.ToObjects(base),
		put: func(ctx context.Context, key string, o []byte, v storage.Version) error {
			if key == wsp.ControlRef && put != nil {
				if err := put(ctx, o); err != nil {
					return err
				}
			}
			return storagetest.ToObjects(base).Put(ctx, key, o, v)
		}})
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

// Another device founding the workspace first must not leave this repository
// trusting a genesis that is not the real one.
func TestLosingTheFoundingRaceLeavesNoGenesisBehind(t *testing.T) {
	a := foundingApp(t, func(context.Context, []byte) error { return storage.ErrConflict })
	_, err := a.InitializeRepository(bg)
	if !apperr.Is(err, apperr.CodeInvalidArgument) {
		t.Fatalf("init after losing the race: %v", err)
	}
	if g := genesisInConfig(t, a); g != "" {
		t.Fatalf("control_genesis %q was kept after losing the race", g)
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
	diff, err := alice.DiffHistory(bg, "default", len(entries)-1, len(entries))
	if err != nil {
		t.Fatalf("diff across a removed member's snapshot: %v", err)
	}
	if len(diff.Added) != 1 || diff.Added[0] != "BOB" {
		t.Fatalf("diff = %+v", diff)
	}
	if err := alice.RestoreHistory(bg, "default", len(entries)); err != nil {
		t.Fatalf("restore a removed member's snapshot: %v", err)
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
	alice.Storage = storagetest.Wrap(base, &hookedStorage{Objects: storagetest.ToObjects(base),
		get: func(ctx context.Context, key string) ([]byte, storage.Version, error) {
			if key == secretsTag("default") && !moved {
				moved = true
				s, err := (&App{Storage: base, Identities: alice.Identities, CheckpointDir: t.TempDir(), RepositoryDir: alice.RepositoryDir}).openSession(ctx)
				if err != nil {
					t.Error(err)
				} else {
					defer s.Close()
					if _, err := wsp.UpdateControl(ctx, base, s.head, s.signer, func(c *wsp.Control) error {
						c.Principals = append(c.Principals, extra)
						return nil
					}); err != nil {
						t.Error(err)
					}
				}
			}
			return storagetest.ToObjects(base).Get(ctx, key)
		}})
	if err := alice.AddSecret(bg, "default", "NEW", "value"); err != nil {
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
	if !moved || s.head.Generation != 1 || read.state.ControlGeneration != 1 {
		t.Fatalf("moved=%v head=%d state written under generation %d: it still used the old member list", moved, s.head.Generation, read.state.ControlGeneration)
	}
}
