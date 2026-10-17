package app

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	apptest "github.com/enbu-net/enbu/app/apptest"
	"github.com/enbu-net/enbu/pkg/apperr"
	"github.com/enbu-net/enbu/pkg/config"
	"github.com/enbu-net/enbu/pkg/signing"
	"github.com/enbu-net/enbu/pkg/storage"
	"github.com/enbu-net/enbu/pkg/storage/storagetest"
	"github.com/enbu-net/enbu/pkg/wsp"
	"github.com/opencontainers/go-digest"
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

// A request carries no authority. Anything in the request namespace that is not
// a validly self-signed request of this workspace is only noise.
func TestForgedJoinRequestsAreIgnored(t *testing.T) {
	alice := newAlice(t)
	mallory, victim := newDevice(t, alice), newDevice(t, alice)
	mRes := requestJoin(t, mallory)
	ws := mustWorkspace(t, alice)

	// Mallory's request body under the victim's signature, garbage, and a
	// request for another workspace.
	plant := func(blob []byte) {
		t.Helper()
		if _, err := wsp.PublishJoinRequest(bg, alice.Storage, blob); err != nil {
			t.Fatal(err)
		}
	}
	plant([]byte("garbage"))
	vs, _, _, err := victim.Identities.CreateSigner(ws)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = vs.Close() }()
	id, _, _, err := victim.Identities.Create(ws)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = id.Close() }()
	other, err := wsp.NewJoinRequest("0192f3a0-7c1e-7a55-9d3c-000000000000", id.Recipient().String(), time.Now(), vs)
	if err != nil {
		t.Fatal(err)
	}
	plant(other)
	good, err := wsp.NewJoinRequest(ws, id.Recipient().String(), time.Now(), vs)
	if err != nil {
		t.Fatal(err)
	}
	signed, _ := wsp.DecodeSigned(good)
	ms, _ := mallory.Identities.LoadSigner(ws)
	defer func() { _ = ms.Close() }()
	forgedSig, _ := ms.Sign(signing.DomainJoin, signed.Body)
	forged, _ := wsp.Signed{Body: signed.Body, Signature: forgedSig}.Encode()
	plant(forged)

	reqs, err := alice.ListJoinRequests(bg)
	if err != nil {
		t.Fatal(err)
	}
	if len(reqs) != 1 || reqs[0].DeviceID != mRes.DeviceID {
		t.Fatalf("forged requests listed: %+v", reqs)
	}
	if err := alice.ApproveMember(bg, string(vs.Public().DeviceID())); !apperr.Is(err, apperr.CodeInvalidArgument) {
		t.Fatalf("approved a device whose only request was forged: %v", err)
	}
}

func TestForgedControlIgnored(t *testing.T) {
	alice := newAlice(t)
	mallory := newDevice(t, alice)
	requestJoin(t, mallory)
	ms, _ := mallory.Identities.LoadSigner(mustWorkspace(t, mallory))
	defer func() { _ = ms.Close() }()
	s, _ := alice.openSession(bg)
	defer s.Close()
	self := wsp.Principal{ID: ms.Public().DeviceID(), Signing: ms.Public(), Recipient: mustRecipient(t, alice), Admin: true}
	forged, err := wsp.SignControl(wsp.Control{Workspace: s.workspace, Parents: []digest.Digest{s.head.Digest}, Height: s.head.Height + 1, Author: self.ID,
		Principals: append(append([]wsp.Principal{}, s.head.Principals...), self)}, ms)
	if err != nil {
		t.Fatal(err)
	}
	if err := alice.Storage.Publish(bg, storage.Object{Kind: storage.KindControl, Rev: digest.FromBytes(forged), Head: forged}); err != nil {
		t.Fatal(err)
	}
	members, err := alice.ListMembers(bg)
	if err != nil || len(members) != 1 {
		t.Fatalf("a forged control changed the members: %+v %v", members, err)
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
			alice.Storage = failStatePublishes(base, nil)
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
	alice.Storage = failStatePublishes(base, attempted)
	err = alice.ApproveMember(bg, device.DeviceID)
	if !apperr.Is(err, apperr.CodeReencryptIncomplete) {
		t.Fatalf("error = %v", err)
	}
	// One environment failing must not stop the others from being attempted.
	if attempted[storage.StateScope(cfg.WorkspaceID, cfg.Resource("default"))] == 0 || attempted[storage.StateScope(cfg.WorkspaceID, cfg.Resource("dev"))] == 0 {
		t.Fatalf("attempts per ref: %v", attempted)
	}
	for _, env := range []string{"default", "dev"} {
		if !strings.Contains(err.Error(), "re-encrypting "+env) {
			t.Fatalf("the error does not name %s: %v", env, err)
		}
	}
}

// A removed member's revision is still history: it is judged by the control it
// was written under, not by who is a member now. It is not current, though.
func TestHistoricalStateOfARemovedAuthorStillVerifies(t *testing.T) {
	alice := newEmptyAlice(t)
	bob := approved(t, alice)
	bs, err := bob.openSession(bg)
	if err != nil {
		t.Fatal(err)
	}
	defer bs.Close()
	bobsEnv := "staging"
	if _, err := bs.writeState(bg, bobsEnv, map[string]string{"A": "by bob"}, nil); err != nil {
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
	if _, err := as.readResource(bg, bobsEnv, nil, true); !apperr.Is(err, apperr.CodeUntrusted) {
		t.Fatalf("a removed author's revision is not current: %v", err)
	}
	sv, err := as.loadResource(bg, bobsEnv)
	if err != nil || len(sv.States) != 1 {
		t.Fatalf("history by a removed author: %v", err)
	}
	for _, st := range sv.States {
		secrets, err := as.decrypt(bg, st) // alice could decrypt it: she was a recipient then
		if err != nil || secrets["A"] != "by bob" {
			t.Fatalf("secrets = %v %v", secrets, err)
		}
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
	alice.Storage = storagetest.Wrap(base, storagetest.Hooks{
		Publish: func(ctx context.Context, next storage.Store, o storage.Object) error {
			if o.Kind == storage.KindState {
				secretWrites++
			}
			return next.Publish(ctx, o)
		},
	})
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

// failStatePublishes lets Control and request objects through and fails every
// State publish, counting the attempts per scope into attempted when it is set.
func failStatePublishes(base storage.Store, attempted map[string]int) storage.Store {
	return storagetest.Wrap(base, storagetest.Hooks{
		Publish: func(ctx context.Context, next storage.Store, o storage.Object) error {
			if o.Kind != storage.KindState {
				return next.Publish(ctx, o)
			}
			if attempted != nil {
				attempted[o.Scope]++
			}
			return errors.New("storage unavailable")
		},
	})
}
