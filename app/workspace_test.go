package app

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"

	agecrypto "filippo.io/age"
	"github.com/enbu-net/enbu/pkg/age"
	"github.com/enbu-net/enbu/pkg/apperr"
	"github.com/enbu-net/enbu/pkg/bundle"
	"github.com/enbu-net/enbu/pkg/config"
	"github.com/enbu-net/enbu/pkg/signing"
	"github.com/enbu-net/enbu/pkg/storage"
	storagetest "github.com/enbu-net/enbu/pkg/storage/storagetest"
	"github.com/enbu-net/enbu/pkg/wsp"
	"github.com/opencontainers/go-digest"
)

// A fresh environment keeps these tests independent of any secrets alice wrote.
const stagingRef = "secrets-staging"

func writeStaging(t *testing.T, s *session, secrets map[string]string, cur *stateRead) digest.Digest {
	t.Helper()
	var expected storage.Version
	if cur != nil {
		expected = cur.version
	}
	d, err := s.writeState(bg, stagingRef, "staging", secrets, cur, expected)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// encryptForTest encrypts secrets for the recipients of the verified Control.
func encryptForTest(s *session, secrets map[string]string) ([]byte, error) {
	return age.EncryptForPublicKeys(bundle.Marshal(secrets), s.head.Recipients())
}

func TestSessionStateRoundTrip(t *testing.T) {
	alice := newAlice(t)
	s, err := alice.openSession(bg)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	writeStaging(t, s, map[string]string{"A": "1"}, nil)
	first, err := s.readState(bg, stagingRef, "staging", true)
	if err != nil || first.secrets["A"] != "1" || first.state.Sequence != 1 {
		t.Fatalf("first read: %+v %v", first, err)
	}
	writeStaging(t, s, map[string]string{"A": "2"}, first)
	second, err := s.readState(bg, stagingRef, "staging", true)
	if err != nil || second.secrets["A"] != "2" || second.state.Sequence != 2 || second.state.Previous != first.state.Digest {
		t.Fatalf("second read: %+v %v", second, err)
	}
}

// The ciphertext is only readable by the members of the verified Control.
func TestSessionEncryptsForControlMembersOnly(t *testing.T) {
	alice := newAlice(t)
	s, err := alice.openSession(bg)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	writeStaging(t, s, map[string]string{"A": "1"}, nil)
	read, err := s.readState(bg, stagingRef, "staging", false)
	if err != nil {
		t.Fatal(err)
	}
	stranger, err := agecrypto.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, err := readBlob(bg, alice.Storage, read.state.Ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decryptSecretsObject(ciphertext, stranger); err == nil {
		t.Fatal("an identity outside the control decrypted the state")
	}
	if got := s.head.Recipients(); len(got) != 1 {
		t.Fatalf("recipients = %v", got)
	}
}

func TestSessionRejectsUnsignedState(t *testing.T) {
	alice := newAlice(t)
	s, err := alice.openSession(bg)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	// Real ciphertext for the real recipients, but nobody signed a state for it.
	raw, err := encryptForTest(s, map[string]string{"A": "evil"})
	if err != nil {
		t.Fatal(err)
	}
	if err := putRef(bg, alice.Storage, stagingRef, raw, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := s.readState(bg, stagingRef, "staging", true); !apperr.Is(err, apperr.CodeUntrusted) {
		t.Fatalf("unsigned ciphertext accepted: %v", err)
	}
}

func TestSessionRejectsStateSignedByNonMember(t *testing.T) {
	alice := newAlice(t)
	attacker := newDevice(t, alice)
	requestJoin(t, attacker)
	s, err := alice.openSession(bg)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	raw, err := encryptForTest(s, map[string]string{"A": "evil"})
	if err != nil {
		t.Fatal(err)
	}
	blob := signAsOutsider(t, alice, attacker, "staging", raw)
	if err := putRef(bg, alice.Storage, stagingRef, blob, ""); err != nil {
		t.Fatal(err)
	}
	// The signature is valid; the author is simply not a principal.
	if _, err := s.readState(bg, stagingRef, "staging", true); !apperr.Is(err, apperr.CodeUntrusted) {
		t.Fatalf("outsider-signed state accepted: %v", err)
	}
}

func TestSessionRejectsStateOfAnotherResource(t *testing.T) {
	alice := newAlice(t)
	s, err := alice.openSession(bg)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	writeStaging(t, s, map[string]string{"A": "1"}, nil)
	staged, _, err := alice.Storage.Refs.Get(bg, stagingRef)
	if err != nil {
		t.Fatal(err)
	}
	// Replaying a genuine staging state as the dev environment must fail.
	if err := alice.Storage.Refs.Put(bg, "secrets-dev", staged, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := s.readState(bg, "secrets-dev", "dev", true); !apperr.Is(err, apperr.CodeUntrusted) {
		t.Fatalf("state replayed under another environment accepted: %v", err)
	}
}

func TestSessionDetectsStateRollback(t *testing.T) {
	alice := newAlice(t)
	s, err := alice.openSession(bg)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	writeStaging(t, s, map[string]string{"A": "1"}, nil)
	old, _, err := alice.Storage.Refs.Get(bg, stagingRef)
	if err != nil {
		t.Fatal(err)
	}
	first, err := s.readState(bg, stagingRef, "staging", true)
	if err != nil {
		t.Fatal(err)
	}
	writeStaging(t, s, map[string]string{"A": "2"}, first)
	if _, err := s.readState(bg, stagingRef, "staging", true); err != nil { // accepts sequence 2
		t.Fatal(err)
	}
	// Storage serves the previous, genuinely signed state again.
	_, version, _ := alice.Storage.Refs.Get(bg, stagingRef)
	if err := alice.Storage.Refs.Put(bg, stagingRef, old, version); err != nil {
		t.Fatal(err)
	}
	if _, err := s.readState(bg, stagingRef, "staging", true); !apperr.Is(err, apperr.CodeRollback) {
		t.Fatalf("old state accepted: %v", err)
	}
	// History snapshots are older by design.
	if _, err := s.readState(bg, stagingRef, "staging", false); err != nil {
		t.Fatalf("snapshot read: %v", err)
	}
}

func extraPrincipal(t *testing.T) wsp.Principal {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer := signing.NewEd25519Signer(key)
	id, err := agecrypto.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	return wsp.Principal{ID: signer.Public().DeviceID(), Signing: signer.Public(), Recipient: id.Recipient().String()}
}

func TestOpenControlDetectsRollback(t *testing.T) {
	alice := newAlice(t)
	s, err := alice.openSession(bg)
	if err != nil {
		t.Fatal(err)
	}
	genesis := s.head.Digest
	extra := extraPrincipal(t)
	if _, err := wsp.UpdateControl(bg, s.store, s.head, s.signer, func(c *wsp.Control) error {
		c.Principals = append(c.Principals, extra)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	s.Close()
	if got, err := alice.openControl(bg); err != nil || got.head.Generation != 1 { // records generation 1
		t.Fatalf("control after update: %v", err)
	}
	// Storage hides the change by serving the genesis head again.
	_, version, _ := alice.Storage.Refs.Get(bg, wsp.ControlRef)
	if err := alice.Storage.Refs.Put(bg, wsp.ControlRef, genesis, version); err != nil {
		t.Fatal(err)
	}
	if _, err := alice.openControl(bg); !apperr.Is(err, apperr.CodeRollback) {
		t.Fatalf("old control accepted: %v", err)
	}
}

func TestOpenControlRejectsForgedControl(t *testing.T) {
	alice := newAlice(t)
	mallory := newDevice(t, alice)
	requestJoin(t, mallory)
	ms, err := mallory.Identities.LoadSigner(mustWorkspace(t, mallory))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ms.Close() }()
	s, err := alice.openSession(bg)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	self := wsp.Principal{ID: ms.Public().DeviceID(), Signing: ms.Public(), Recipient: s.head.Principals[0].Recipient, Admin: true}
	forged, err := wsp.SignControl(wsp.Control{Workspace: s.workspace, Generation: 1, Previous: s.head.Digest, Author: self.ID,
		Principals: append(append([]wsp.Principal{}, s.head.Principals...), self)}, ms)
	if err != nil {
		t.Fatal(err)
	}
	_, version, _ := alice.Storage.Refs.Get(bg, wsp.ControlRef)
	if err := putRef(bg, alice.Storage, wsp.ControlRef, forged, version); err != nil {
		t.Fatal(err)
	}
	if _, err := alice.openControl(bg); !apperr.Is(err, apperr.CodeUntrusted) {
		t.Fatalf("forged control accepted: %v", err)
	}
}

// WorkspaceID alone is not enough to bootstrap a client.
func TestOpenControlNeedsTrustedGenesis(t *testing.T) {
	alice := newAlice(t)
	cfg, err := alice.loadProject()
	if err != nil {
		t.Fatal(err)
	}
	genuine := cfg.ControlGenesis
	cfg.ControlGenesis = ""
	if err := config.SaveProjectTo(alice.RepositoryDir, cfg); err != nil {
		t.Fatal(err)
	}
	if _, err := alice.openControl(bg); !apperr.Is(err, apperr.CodeInvalidArgument) {
		t.Fatalf("opened without a genesis: %v", err)
	}
	cfg.ControlGenesis = "sha256:" + string(bytes.Repeat([]byte("0"), 64))
	if err := config.SaveProjectTo(alice.RepositoryDir, cfg); err != nil {
		t.Fatal(err)
	}
	if _, err := alice.openControl(bg); !apperr.Is(err, apperr.CodeUntrusted) {
		t.Fatalf("opened with a wrong genesis: %v", err)
	}
	cfg.ControlGenesis = genuine
	if err := config.SaveProjectTo(alice.RepositoryDir, cfg); err != nil {
		t.Fatal(err)
	}
	if _, err := alice.openControl(bg); err != nil {
		t.Fatalf("genuine genesis rejected: %v", err)
	}
}

func TestOpenSessionRequiresMembership(t *testing.T) {
	alice := newAlice(t)
	bob := newDevice(t, alice)
	requestJoin(t, bob)
	if _, err := bob.openSession(bg); !apperr.Is(err, apperr.CodeNotMember) {
		t.Fatalf("pending device opened a session: %v", err)
	}
}

func TestOpenControlWithoutControlIsIncompatible(t *testing.T) {
	a := newTestApp(t, "owner", "repo", "default", mustKeyPair(t), nil)
	cfg, err := a.loadProject()
	if err != nil {
		t.Fatal(err)
	}
	cfg.ControlGenesis = "sha256:" + string(bytes.Repeat([]byte("1"), 64))
	if err := config.SaveProjectTo(a.RepositoryDir, cfg); err != nil {
		t.Fatal(err)
	}
	other := &App{Storage: newMemRegistry(), Identities: a.Identities, CheckpointDir: t.TempDir(), RepositoryDir: a.RepositoryDir}
	if err := putRef(bg, other.Storage, workspaceKey, []byte(testWorkspaceID), ""); err != nil {
		t.Fatal(err)
	}
	if _, err := other.openControl(bg); !apperr.Is(err, apperr.CodeIncompatibleStorage) {
		t.Fatalf("storage without a control: %v", err)
	}
}

// A state that this device would refuse to read back must not be published.
func TestWriteStateDoesNotPublishBelowTheCheckpoint(t *testing.T) {
	alice := newAlice(t)
	s, err := alice.openSession(bg)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	writeStaging(t, s, map[string]string{"A": "1"}, nil)
	read, err := s.readState(bg, stagingRef, "staging", true)
	if err != nil {
		t.Fatal(err)
	}
	writeStaging(t, s, map[string]string{"A": "2"}, read) // checkpoint is now sequence 2
	// A fresh chain for the same environment under another ref would start at
	// sequence 1, below what this device has accepted.
	_, err = s.writeState(bg, "secrets-staging-copy", "staging", map[string]string{"A": "x"}, nil, "")
	if !apperr.Is(err, apperr.CodeRollback) {
		t.Fatalf("writing below the checkpoint: %v", err)
	}
	if _, _, err := alice.Storage.Refs.Get(bg, "secrets-staging-copy"); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("the ref was created anyway: %v", err)
	}
}

// An admin removing a member between "session opened" and "ciphertext
// published" must not result in new ciphertext for the removed recipient.
func TestWriteStateRefusesToPublishAfterTheControlMoved(t *testing.T) {
	alice := newAlice(t)
	s, err := alice.openSession(bg)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	other, err := alice.openSession(bg) // another admin session on the same control
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	extra := extraPrincipal(t)
	if _, err := wsp.UpdateControl(bg, other.store, other.head, other.signer, func(c *wsp.Control) error {
		c.Principals = append(c.Principals, extra)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	_, err = s.writeState(bg, stagingRef, "staging", map[string]string{"A": "1"}, nil, "")
	if !errors.Is(err, errControlMoved) {
		t.Fatalf("write on a stale control: %v", err)
	}
	if _, _, err := alice.Storage.Refs.Get(bg, stagingRef); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("a state was published anyway: %v", err)
	}
	// A fresh session sees the new member and encrypts for it.
	fresh, err := alice.openSession(bg)
	if err != nil {
		t.Fatal(err)
	}
	defer fresh.Close()
	if _, err := fresh.writeState(bg, stagingRef, "staging", map[string]string{"A": "1"}, nil, ""); err != nil {
		t.Fatalf("write on the current control: %v", err)
	}
}

// On a backend whose ref update is not atomic, another writer can overwrite
// ours right after it. That must surface as a conflict and leave the checkpoint
// alone, so the retry starts from the state that really is current.
func TestWriteStateReportsALostUpdate(t *testing.T) {
	alice := newAlice(t)
	base := alice.Storage
	alice.Storage = storagetest.Wrap(base, &hookedStorage{Objects: storagetest.ToObjects(base),
		put: func(ctx context.Context, key string, o []byte, v storage.Version) error {
			objects := storagetest.ToObjects(base)
			if err := objects.Put(ctx, key, o, v); err != nil || key != stagingRef {
				return err
			}
			// A concurrent writer's update lands on top of ours.
			_, now, _ := objects.Get(ctx, key)
			return objects.Put(ctx, key, []byte("someone else's state"), now)
		}})
	s, err := alice.openSession(bg)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	_, err = s.writeState(bg, stagingRef, "staging", map[string]string{"A": "1"}, nil, "")
	if !apperr.Is(err, apperr.CodeConflict) {
		t.Fatalf("a lost update was not reported as a conflict: %v", err)
	}
	if cp, _ := s.cps.State("secrets/staging"); cp != nil {
		t.Fatalf("the checkpoint recorded a state that was overwritten: %+v", cp)
	}
}

// principalOf is the member entry a device would get in the control.
func principalOf(t *testing.T, d *App) wsp.Principal {
	t.Helper()
	ws := mustWorkspace(t, d)
	id, _, _, err := d.Identities.Create(ws)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = id.Close() }()
	signer, err := d.Identities.LoadSigner(ws)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = signer.Close() }()
	return wsp.Principal{ID: signer.Public().DeviceID(), Signing: signer.Public(), Recipient: id.Recipient().String()}
}

func changeControl(t *testing.T, a *App, mutate func(*wsp.Control)) {
	t.Helper()
	s, err := a.openSession(bg)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err := wsp.UpdateControl(bg, s.store, s.head, s.signer, func(c *wsp.Control) error { mutate(c); return nil }); err != nil {
		t.Fatal(err)
	}
}

// An admin must be able to take over what a member last wrote when removing
// them, so a state this device accepted stays acceptable. A state the removed
// member signs afterwards was never accepted and must not be.
func TestSessionKeepsAnAcceptedStateAfterItsAuthorIsRemoved(t *testing.T) {
	alice := newAlice(t)
	bob := newDevice(t, alice)
	requestJoin(t, bob)
	bobsEntry := principalOf(t, bob)
	changeControl(t, alice, func(c *wsp.Control) { c.Principals = append(c.Principals, bobsEntry) })

	s, err := alice.openSession(bg)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := encryptForTest(s, map[string]string{"A": "by bob"})
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
	if err := putRef(bg, alice.Storage, stagingRef, signAsOutsider(t, alice, bob, "staging", raw), ""); err != nil {
		t.Fatal(err)
	}
	s, err = alice.openSession(bg)
	if err != nil {
		t.Fatal(err)
	}
	if read, err := s.readState(bg, stagingRef, "staging", true); err != nil || read.secrets["A"] != "by bob" {
		t.Fatalf("bob's state while he is a member: %v", err)
	}
	s.Close()

	changeControl(t, alice, func(c *wsp.Control) {
		kept := c.Principals[:0:0]
		for _, p := range c.Principals {
			if p.ID != bobsEntry.ID {
				kept = append(kept, p)
			}
		}
		c.Principals = kept
	})
	s, err = alice.openSession(bg)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if read, err := s.readState(bg, stagingRef, "staging", true); err != nil || read.secrets["A"] != "by bob" {
		t.Fatalf("the state alice already accepted was refused after bob left: %v", err)
	}

	// Bob signs something new after the removal.
	_, version, _ := alice.Storage.Refs.Get(bg, stagingRef)
	forged, err := encryptForTest(s, map[string]string{"A": "bob again"})
	if err != nil {
		t.Fatal(err)
	}
	if err := putRef(bg, alice.Storage, stagingRef, signAsOutsider(t, alice, bob, "staging", forged), version); err != nil {
		t.Fatal(err)
	}
	if _, err := s.readState(bg, stagingRef, "staging", true); !apperr.Is(err, apperr.CodeUntrusted) {
		t.Fatalf("a state signed after the removal was accepted: %v", err)
	}
}
