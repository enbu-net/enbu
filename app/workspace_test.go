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
	"github.com/enbu-net/enbu/pkg/storage/storagetest"
	"github.com/enbu-net/enbu/pkg/wsp"
	"github.com/opencontainers/go-digest"
)

// A fresh environment keeps these tests independent of any secrets alice wrote.
const stagingEnv = "staging"

func writeStaging(t *testing.T, s *session, secrets map[string]string, parents ...digest.Digest) digest.Digest {
	t.Helper()
	rev, err := s.writeState(bg, stagingEnv, secrets, parents)
	if err != nil {
		t.Fatal(err)
	}
	return rev
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
	first := writeStaging(t, s, map[string]string{"A": "1"})
	read, err := s.readResource(bg, stagingEnv, nil, true)
	if err != nil || read.secrets["A"] != "1" || len(read.heads) != 1 || read.heads[0].Digest != first {
		t.Fatalf("first read: %+v %v", read, err)
	}
	second := writeStaging(t, s, map[string]string{"A": "2"}, first)
	read, err = s.readResource(bg, stagingEnv, nil, true)
	if err != nil || read.secrets["A"] != "2" || read.heads[0].Digest != second || read.heads[0].Parents[0] != first {
		t.Fatalf("second read: %+v %v", read, err)
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
	rev := writeStaging(t, s, map[string]string{"A": "1"})
	read, err := s.readResource(bg, stagingEnv, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	stranger, err := agecrypto.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, err := storage.ReadBlob(bg, alice.Storage, storage.KindState, read.heads[0].Scope(), rev, 0, storage.MaxPayloadBytes)
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

// Anything a writer to storage publishes that is not a validly signed State of a
// member carries no authority. It is skipped, so it neither injects secrets nor
// stops genuine ones from being read.
func TestSessionIgnoresRevisionsWithoutAuthority(t *testing.T) {
	alice := newAlice(t)
	attacker := newDevice(t, alice)
	requestJoin(t, attacker)
	s, err := alice.openSession(bg)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ws := mustWorkspace(t, alice)
	resource := s.resource(stagingEnv)
	scope := storage.StateScope(ws, resource)
	raw, err := encryptForTest(s, map[string]string{"A": "evil"})
	if err != nil {
		t.Fatal(err)
	}

	// Real ciphertext for the real recipients inside a "state" nobody signed.
	garbage := []byte("not a signed state")
	if err := alice.Storage.Publish(bg, storage.Object{Kind: storage.KindState, Scope: scope, Rev: digest.FromBytes(garbage), Head: garbage, Blobs: [][]byte{raw}}); err != nil {
		t.Fatal(err)
	}
	// A valid signature by a device that is not a principal.
	publishRevision(t, alice.Storage, attacker, ws, resource, s.head.Digest, raw)
	if _, err := s.readResource(bg, stagingEnv, nil, true); !IsNotFoundError(err) {
		t.Fatalf("revisions without authority were read: %v", err)
	}

	genuine := writeStaging(t, s, map[string]string{"A": "genuine"})
	read, err := s.readResource(bg, stagingEnv, nil, true)
	if err != nil || read.secrets["A"] != "genuine" || len(read.heads) != 1 || read.heads[0].Digest != genuine {
		t.Fatalf("genuine head not read beside the junk: %+v %v", read, err)
	}
}

func TestSessionRejectsStateOfAnotherResource(t *testing.T) {
	alice := newAlice(t)
	s, err := alice.openSession(bg)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	rev := writeStaging(t, s, map[string]string{"A": "1"})
	src := storage.StateScope(s.workspace, s.resource(stagingEnv))
	head, err := alice.Storage.FetchHead(bg, storage.KindState, src, rev)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, err := storage.ReadBlob(bg, alice.Storage, storage.KindState, src, rev, 0, storage.MaxPayloadBytes)
	if err != nil {
		t.Fatal(err)
	}
	// Replaying a genuine staging state as the dev environment must fail.
	replay := storage.Object{Kind: storage.KindState, Scope: storage.StateScope(s.workspace, s.resource("dev")), Rev: rev, Head: head, Blobs: [][]byte{ciphertext}}
	if err := alice.Storage.Publish(bg, replay); err != nil {
		t.Fatal(err)
	}
	if _, err := s.readResource(bg, "dev", nil, true); !IsNotFoundError(err) {
		t.Fatalf("state replayed under another environment accepted: %v", err)
	}
}

func hide(base storage.Store, hidden ...digest.Digest) storage.Store {
	is := func(d digest.Digest) bool {
		for _, h := range hidden {
			if h == d {
				return true
			}
		}
		return false
	}
	return storagetest.Wrap(base, storagetest.Hooks{
		Discover: func(ctx context.Context, next storage.Store, kind storage.Kind, scope string) ([]digest.Digest, error) {
			revs, err := next.Discover(ctx, kind, scope)
			var out []digest.Digest
			for _, r := range revs {
				if !is(r) {
					out = append(out, r)
				}
			}
			return out, err
		},
		FetchHead: func(ctx context.Context, next storage.Store, kind storage.Kind, scope string, rev digest.Digest) ([]byte, error) {
			if is(rev) {
				return nil, storage.ErrNotFound
			}
			return next.FetchHead(ctx, kind, scope, rev)
		},
	})
}

func TestSessionDetectsStateRollback(t *testing.T) {
	alice := newAlice(t)
	s, err := alice.openSession(bg)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	first := writeStaging(t, s, map[string]string{"A": "1"})
	second := writeStaging(t, s, map[string]string{"A": "2"}, first)
	if _, err := s.readResource(bg, stagingEnv, nil, true); err != nil { // accepts the second revision
		t.Fatal(err)
	}
	// Storage stops showing the newest revision.
	real := alice.Storage
	alice.Storage = hide(real, second)
	s.store = alice.Storage
	if _, err := s.readResource(bg, stagingEnv, nil, true); !apperr.Is(err, apperr.CodeRollback) {
		t.Fatalf("storage that lost an accepted revision: %v", err)
	}
	// Seeing it again is not a rollback: a stale listing is temporary.
	s.store = real
	if read, err := s.readResource(bg, stagingEnv, nil, true); err != nil || read.secrets["A"] != "2" {
		t.Fatalf("after storage recovered: %v", err)
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
	extra := extraPrincipal(t)
	v, err := wsp.UpdateControl(bg, s.store, s.view, s.signer, func(c *wsp.Control) error {
		c.Principals = append(c.Principals, extra)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
	if got, err := alice.openControl(bg); err != nil || got.head.Digest != v.Digest { // records the new head
		t.Fatalf("control after update: %v", err)
	}
	// Storage hides the change.
	real := alice.Storage
	alice.Storage = hide(real, v.Digest)
	if _, err := alice.openControl(bg); !apperr.Is(err, apperr.CodeRollback) {
		t.Fatalf("old control accepted: %v", err)
	}
	alice.Storage = real
	if _, err := alice.openControl(bg); err != nil {
		t.Fatalf("storage recovered: %v", err)
	}
}

// A Control signed by someone who is not an admin is not part of the DAG, so
// publishing one changes nothing for anybody.
func TestOpenControlIgnoresForgedControl(t *testing.T) {
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
	forged, err := wsp.SignControl(wsp.Control{Workspace: s.workspace, Parents: []digest.Digest{s.head.Digest}, Height: s.head.Height + 1, Author: self.ID,
		Principals: append(append([]wsp.Principal{}, s.head.Principals...), self)}, ms)
	if err != nil {
		t.Fatal(err)
	}
	if err := alice.Storage.Publish(bg, storage.Object{Kind: storage.KindControl, Rev: digest.FromBytes(forged), Head: forged}); err != nil {
		t.Fatal(err)
	}
	got, err := alice.openControl(bg)
	if err != nil {
		t.Fatal(err)
	}
	if got.head.Digest != s.head.Digest {
		t.Fatal("a forged control became the head")
	}
	if _, ok := got.head.Principal(self.ID); ok {
		t.Fatal("the forger became a principal")
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
	if _, err := alice.openControl(bg); !apperr.Is(err, apperr.CodeIncompatibleStorage) {
		t.Fatalf("opened with a genesis storage does not hold: %v", err)
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
	other := &App{Storage: newMemRegistry(), Identities: a.Identities, CheckpointDir: t.TempDir(), RepositoryDir: a.RepositoryDir}
	if _, err := other.openControl(bg); !apperr.Is(err, apperr.CodeIncompatibleStorage) {
		t.Fatalf("storage without a control: %v", err)
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
	if _, err := wsp.UpdateControl(bg, other.store, other.view, other.signer, func(c *wsp.Control) error {
		c.Principals = append(c.Principals, extra)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	_, err = s.writeState(bg, stagingEnv, map[string]string{"A": "1"}, nil)
	if !errors.Is(err, errControlMoved) {
		t.Fatalf("write on a stale control: %v", err)
	}
	if revs := revisionsOf(t, alice, stagingEnv); len(revs) != 0 {
		t.Fatalf("a state was published anyway: %v", revs)
	}
	// A fresh session sees the new member and encrypts for it.
	fresh, err := alice.openSession(bg)
	if err != nil {
		t.Fatal(err)
	}
	defer fresh.Close()
	if _, err := fresh.writeState(bg, stagingEnv, map[string]string{"A": "1"}, nil); err != nil {
		t.Fatalf("write on the current control: %v", err)
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
	if _, err := wsp.UpdateControl(bg, s.store, s.view, s.signer, func(c *wsp.Control) error { mutate(c); return nil }); err != nil {
		t.Fatal(err)
	}
}

// An admin must be able to take over what a member last wrote when removing
// them, so a revision this device accepted stays acceptable. A revision the
// removed member signs afterwards was never accepted and is set aside.
func TestSessionKeepsAnAcceptedStateAfterItsAuthorIsRemoved(t *testing.T) {
	alice := newAlice(t)
	bob := newDevice(t, alice)
	requestJoin(t, bob)
	bobsEntry := principalOf(t, bob)
	changeControl(t, alice, func(c *wsp.Control) { c.Principals = append(c.Principals, bobsEntry) })

	ws := mustWorkspace(t, alice)
	s, err := alice.openSession(bg)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := encryptForTest(s, map[string]string{"A": "by bob"})
	if err != nil {
		t.Fatal(err)
	}
	bobsRev := publishRevision(t, alice.Storage, bob, ws, s.resource(stagingEnv), s.head.Digest, raw)
	if read, err := s.readResource(bg, stagingEnv, nil, true); err != nil || read.secrets["A"] != "by bob" {
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
	if read, err := s.readResource(bg, stagingEnv, nil, true); err != nil || read.secrets["A"] != "by bob" {
		t.Fatalf("the state alice already accepted was refused after bob left: %v", err)
	}

	// Bob claims the control he knew and signs something new on top of his own revision.
	oldControl := s.head.Parents[0]
	forged, err := encryptForTest(s, map[string]string{"A": "bob again"})
	if err != nil {
		t.Fatal(err)
	}
	publishRevision(t, alice.Storage, bob, ws, s.resource(stagingEnv), oldControl, forged, bobsRev)
	read, err := s.readResource(bg, stagingEnv, nil, true)
	if err != nil || read.secrets["A"] != "by bob" || len(read.heads) != 1 || read.heads[0].Digest != bobsRev {
		t.Fatalf("a revision signed after the removal changed what is read: %+v %v", read, err)
	}
}

// A removed member whose only revision this device never accepted cannot be read.
func TestSessionSetsAsideAHeadOfAMemberRemovedBeforeItWasAccepted(t *testing.T) {
	alice := newAlice(t)
	bob := newDevice(t, alice)
	requestJoin(t, bob)
	bobsEntry := principalOf(t, bob)
	changeControl(t, alice, func(c *wsp.Control) { c.Principals = append(c.Principals, bobsEntry) })
	s, err := alice.openSession(bg)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := encryptForTest(s, map[string]string{"A": "by bob"})
	publishRevision(t, alice.Storage, bob, mustWorkspace(t, alice), s.resource(stagingEnv), s.head.Digest, raw)
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
	if _, err := s.readResource(bg, stagingEnv, nil, true); !apperr.Is(err, apperr.CodeUntrusted) {
		t.Fatalf("a head by a removed member, never accepted: %v", err)
	}
}
