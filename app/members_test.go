package app

import (
	"context"
	"errors"
	"strings"
	"testing"

	apptest "github.com/enbu-net/enbu/app/apptest"
	"github.com/enbu-net/enbu/pkg/apperr"
	"github.com/enbu-net/enbu/pkg/config"
	"github.com/enbu-net/enbu/pkg/signing"
	"github.com/enbu-net/enbu/pkg/storage"
	"github.com/enbu-net/enbu/pkg/storage/storagetest"
	"github.com/enbu-net/enbu/pkg/wsp"
)

// approved returns a device that asked to join and has been approved by alice.
func approved(t *testing.T, alice *App) *App {
	t.Helper()
	bob := newDevice(t, alice)
	if err := alice.ApproveMember(bg, requestJoin(t, bob).DeviceID); err != nil {
		t.Fatal(err)
	}
	return bob
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

func mustRecipient(t *testing.T, a *App) string {
	t.Helper()
	r, err := a.ListRecipients(bg)
	if err != nil || len(r) == 0 {
		t.Fatal(err)
	}
	return r[0].PublicKey
}

func TestMemberCannotApprove(t *testing.T) {
	alice := newEmptyAlice(t)
	bob := approved(t, alice)
	carol := newDevice(t, alice)
	res := requestJoin(t, carol)
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

// A request that is not signed by the device it names is only noise.
func TestForgedJoinRequestsAreIgnored(t *testing.T) {
	alice := newAlice(t)
	mallory, victim := newDevice(t, alice), newDevice(t, alice)
	mRes := requestJoin(t, mallory)
	vRes := requestJoin(t, victim)
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

func TestForgedControlRejected(t *testing.T) {
	alice := newAlice(t)
	mallory := newDevice(t, alice)
	requestJoin(t, mallory)
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

func TestMembershipChangeReportsIncompleteReencryption(t *testing.T) {
	for _, op := range []string{"approve", "remove"} {
		t.Run(op, func(t *testing.T) {
			alice := newAlice(t)
			var target string
			if op == "approve" {
				bob := newDevice(t, alice)
				target = requestJoin(t, bob).DeviceID
			} else {
				target = mustMember(t, alice, approved(t, alice)).DeviceID
			}
			base := alice.Storage
			// The control may change, but writing any secret state fails.
			alice.Storage = storagetest.Wrap(base, &hookedStorage{Objects: storagetest.ToObjects(base),
				put: func(ctx context.Context, key string, o []byte, v storage.Version) error {
					if key == wsp.ControlRef {
						return storagetest.ToObjects(base).Put(ctx, key, o, v)
					}
					return errors.New("storage unavailable")
				}})
			var err error
			if op == "approve" {
				err = alice.ApproveMember(bg, target)
			} else {
				err = alice.RemoveMember(bg, target)
			}
			if !apperr.Is(err, apperr.CodeReencryptIncomplete) {
				t.Fatalf("error = %v, want reencrypt_incomplete", err)
			}
			// The Control did change, which is why the caller must be told.
			alice.Storage = base
			members, lerr := alice.ListMembers(bg)
			if lerr != nil {
				t.Fatal(lerr)
			}
			want := 2
			if op == "remove" {
				want = 1
			}
			if len(members) != want {
				t.Fatalf("members = %d, want %d", len(members), want)
			}
			// Sync finishes the job the error asked for.
			if err := alice.SyncSecrets(bg, "default"); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestMemberChangeKeepsValidationCode(t *testing.T) {
	alice := newAlice(t)
	bob := approved(t, alice)
	id := mustMember(t, alice, bob).DeviceID
	if err := alice.ApproveMember(bg, id); !apperr.Is(err, apperr.CodeInvalidArgument) {
		t.Fatalf("approving an existing member: %v", err)
	}
	if err := alice.RemoveMember(bg, strings.Repeat("0", 64)); !apperr.Is(err, apperr.CodeInvalidArgument) {
		t.Fatalf("removing a stranger: %v", err)
	}
}

// newEmptyAlice is a founder whose workspace holds no secrets, so membership
// changes have nothing to re-encrypt.
func newEmptyAlice(t *testing.T) *App {
	t.Helper()
	a := newTestApp(t, "owner", "repo", "default", mustKeyPair(t), nil)
	// A no-op when the workspace was initialized through the real flow.
	if err := apptest.Control(bg, a.Storage, a.RepositoryDir, a.Identities); err != nil {
		t.Fatal(err)
	}
	return a
}

func TestPendingRequestsAreNotCrowdedOutByExistingMembers(t *testing.T) {
	alice := newEmptyAlice(t)
	// Two members whose requests are still in storage, then one genuinely pending device.
	approved(t, alice)
	approved(t, alice)
	pending := requestJoin(t, newDevice(t, alice))
	defer func(old int) { maxJoinRequests = old }(maxJoinRequests)
	maxJoinRequests = 1
	got, err := alice.ListJoinRequests(bg)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].DeviceID != pending.DeviceID {
		t.Fatalf("requests = %+v, want only %s", got, pending.DeviceID)
	}
}

func TestJoinRequestListIsCapped(t *testing.T) {
	alice := newEmptyAlice(t)
	for range 3 {
		requestJoin(t, newDevice(t, alice))
	}
	defer func(old int) { maxJoinRequests = old }(maxJoinRequests)
	maxJoinRequests = 2
	got, err := alice.ListJoinRequests(bg)
	if err != nil || len(got) != 2 {
		t.Fatalf("requests = %d %v, want 2", len(got), err)
	}
}

func TestReencryptionTriesEveryEnvironment(t *testing.T) {
	alice := newAlice(t)
	cfg, err := alice.loadProject()
	if err != nil {
		t.Fatal(err)
	}
	if err := cfg.AddEnvironment("dev"); err != nil {
		t.Fatal(err)
	}
	if err := config.SaveProjectTo(alice.RepositoryDir, cfg); err != nil {
		t.Fatal(err)
	}
	if err := alice.AddSecret(bg, "dev", "K", "v"); err != nil {
		t.Fatal(err)
	}
	device := requestJoin(t, newDevice(t, alice))
	base := alice.Storage
	attempted := map[string]int{}
	alice.Storage = storagetest.Wrap(base, &hookedStorage{Objects: storagetest.ToObjects(base),
		put: func(ctx context.Context, key string, o []byte, v storage.Version) error {
			if key == wsp.ControlRef {
				return storagetest.ToObjects(base).Put(ctx, key, o, v)
			}
			attempted[key]++
			return errors.New("storage unavailable")
		}})
	err = alice.ApproveMember(bg, device.DeviceID)
	if !apperr.Is(err, apperr.CodeReencryptIncomplete) {
		t.Fatalf("error = %v", err)
	}
	// One environment failing must not stop the others from being attempted.
	if attempted[secretsTag("default")] == 0 || attempted[secretsTag("dev")] == 0 {
		t.Fatalf("attempts per ref: %v", attempted)
	}
	for _, env := range []string{"default", "dev"} {
		if !strings.Contains(err.Error(), "re-encrypting "+env) {
			t.Fatalf("the error does not name %s: %v", env, err)
		}
	}
}

// A removed member's snapshot is still history: it is judged by the control it
// was written under, not by who is a member now.
func TestHistoricalStateOfARemovedAuthorStillVerifies(t *testing.T) {
	alice := newEmptyAlice(t)
	bob := approved(t, alice)
	bs, err := bob.openSession(bg)
	if err != nil {
		t.Fatal(err)
	}
	defer bs.Close()
	bobsEnv := "staging"
	if _, err := bs.writeState(bg, "hist-bob", bobsEnv, map[string]string{"A": "by bob"}, nil, ""); err != nil {
		t.Fatal(err)
	}
	if err := alice.RemoveMember(bg, mustMember(t, alice, bob).DeviceID); err != nil {
		t.Fatal(err)
	}
	as, err := alice.openSession(bg)
	if err != nil {
		t.Fatal(err)
	}
	defer as.Close()
	if _, err := as.readState(bg, "hist-bob", bobsEnv, true); !apperr.Is(err, apperr.CodeUntrusted) {
		t.Fatalf("a removed author's state is not current: %v", err)
	}
	read, err := as.readState(bg, "hist-bob", bobsEnv, false)
	if err != nil {
		t.Fatalf("history by a removed author: %v", err)
	}
	// Alice could decrypt it because it was encrypted for the members then.
	if read.secrets["A"] != "by bob" {
		t.Fatalf("secrets = %v", read.secrets)
	}
}

// Admin only manages membership; it is not a data permission, so the recipient
// set is unchanged and no secret needs rewriting.
func TestSetAdminDoesNotReencrypt(t *testing.T) {
	alice := newAlice(t)
	bob := approved(t, alice)
	id := mustMember(t, alice, bob).DeviceID
	base := alice.Storage
	secretWrites := 0
	alice.Storage = storagetest.Wrap(base, &hookedStorage{Objects: storagetest.ToObjects(base),
		put: func(ctx context.Context, key string, o []byte, v storage.Version) error {
			if strings.HasPrefix(key, "secrets-") || strings.HasPrefix(key, "hist-") {
				secretWrites++
			}
			return storagetest.ToObjects(base).Put(ctx, key, o, v)
		}})
	if err := alice.SetAdmin(bg, id, true); err != nil {
		t.Fatal(err)
	}
	if err := alice.SetAdmin(bg, id, false); err != nil {
		t.Fatal(err)
	}
	if secretWrites != 0 {
		t.Fatalf("changing the admin flag rewrote secrets %d times", secretWrites)
	}
}
