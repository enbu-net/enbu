package app

import (
	"context"
	"errors"
	"io"
	"slices"
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

func TestRemoveMemberStopsWhenLatestValueCannotBeAccepted(t *testing.T) {
	alice := newAlice(t)
	bob := approved(t, alice)
	target := mustMember(t, alice, bob).DeviceID
	if err := bob.AddSecret(bg, "default", "LATEST", "bob"); err != nil {
		t.Fatal(err)
	}
	base := alice.Storage
	readErr := errors.New("temporary payload failure")
	failed := false
	alice.Storage = storagetest.Wrap(base, storagetest.Hooks{
		OpenPayload: func(ctx context.Context, next storage.Store, kind storage.Kind, scope string, rev digest.Digest) (io.ReadCloser, error) {
			if !failed {
				failed = true
				return nil, readErr
			}
			return next.OpenPayload(ctx, kind, scope, rev)
		},
	})
	if err := alice.RemoveMember(bg, target); !errors.Is(err, readErr) {
		t.Fatalf("removing a member after a failed read: %v", err)
	}
	members, err := alice.ListMembers(bg)
	if err != nil || len(members) != 2 {
		t.Fatalf("membership changed: %+v %v", members, err)
	}
	alice.Storage = base
	if err := alice.RemoveMember(bg, target); err != nil {
		t.Fatal(err)
	}
	if got := listOK(t, alice)["LATEST"]; got != "bob" {
		t.Fatalf("latest value = %q", got)
	}
}

func TestRemoveMemberDoesNotRepublishAncestorAfterConcurrentWrite(t *testing.T) {
	t.Run("visible at first sync read", func(t *testing.T) { checkConcurrentRemovalWrite(t, false) })
	t.Run("visible at final sync read", func(t *testing.T) { checkConcurrentRemovalWrite(t, true) })
}

func checkConcurrentRemovalWrite(t *testing.T, late bool) {
	t.Helper()
	alice := newAlice(t)
	bob := approved(t, alice)
	target := mustMember(t, alice, bob).DeviceID
	var latest digest.Digest
	var statePublishes int
	listLatest := !late
	base := alice.Storage
	alice.Storage = storagetest.Wrap(base, storagetest.Hooks{
		Discover: func(ctx context.Context, next storage.Store, kind storage.Kind, scope string) ([]digest.Digest, error) {
			revisions, err := next.Discover(ctx, kind, scope)
			if kind == storage.KindState && !listLatest && latest != "" {
				revisions = slices.DeleteFunc(slices.Clone(revisions), func(d digest.Digest) bool { return d == latest })
			}
			return revisions, err
		},
		OpenPayload: func(ctx context.Context, next storage.Store, kind storage.Kind, scope string, rev digest.Digest) (io.ReadCloser, error) {
			if kind == storage.KindState && latest != "" {
				listLatest = true
			}
			return next.OpenPayload(ctx, kind, scope, rev)
		},
		Publish: func(ctx context.Context, next storage.Store, object storage.Object) error {
			switch object.Kind {
			case storage.KindControl:
				if err := bob.AddSecret(ctx, "default", "LATEST", "bob"); err != nil {
					return err
				}
				history, err := bob.ListHistory(ctx, "default")
				if err != nil {
					return err
				}
				latest = digest.NewDigestFromEncoded(digest.SHA256, history[len(history)-1].Tag)
			case storage.KindState:
				statePublishes++
			}
			return next.Publish(ctx, object)
		},
	})
	err := alice.RemoveMember(bg, target)
	if !apperr.Is(err, apperr.CodeRemovalWriteRace) {
		t.Fatalf("removal result: %v", err)
	}
	if params := apperr.PayloadOf(err).Params; params["targets"] == "" || !strings.HasSuffix(params["targets"], " "+latest.String()) {
		t.Fatalf("recovery target: %+v", params)
	}
	if latest == "" || statePublishes != 0 {
		t.Fatalf("concurrent revision = %v, re-encryption writes = %d", latest, statePublishes)
	}
	members, err := alice.ListMembers(bg)
	if err != nil || len(members) != 1 || !members[0].Self {
		t.Fatalf("Control was not published: %+v %v", members, err)
	}
	cfg, err := alice.loadProject()
	if err != nil {
		t.Fatal(err)
	}
	scope := storage.StateScope(cfg.WorkspaceID, cfg.Resource("default"))
	if _, err := base.FetchHead(bg, storage.KindState, scope, latest); err != nil {
		t.Fatalf("concurrent revision was lost: %v", err)
	}
	alice.Storage = base
	if err := alice.AddSecret(bg, "default", "CONTINUING", "alice"); err != nil {
		t.Fatal(err)
	}
	preview, err := alice.ReviewRemovedRevision(bg, "default", latest.String(), "")
	if err != nil || len(preview.Diff.Added) != 1 || preview.Diff.Added[0] != "LATEST" {
		t.Fatalf("review: %+v, %v", preview, err)
	}
	if got := listOK(t, alice)["LATEST"]; got != "" {
		t.Fatalf("inspection accepted the revision: %q", got)
	}
	if err := alice.AddSecret(bg, "default", "AFTER_PREVIEW", "keep"); err != nil {
		t.Fatal(err)
	}
	if _, err := alice.ReviewRemovedRevision(bg, cfg.Resource("default"), latest.String(), preview.Baseline); !apperr.Is(err, apperr.CodeRecoveryPreviewChanged) {
		t.Fatalf("stale recovery preview: %v", err)
	}
	preview, err = alice.ReviewRemovedRevision(bg, "default", latest.String(), "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := alice.ReviewRemovedRevision(bg, cfg.Resource("default"), latest.String(), preview.Baseline); err != nil {
		t.Fatal(err)
	}
	if got := listOK(t, alice); got["LATEST"] != "bob" || got["CONTINUING"] != "alice" || got["AFTER_PREVIEW"] != "keep" {
		t.Fatalf("acceptance lost a write: %+v", got)
	}
}

func TestReviewRemovedRevisionRefusesRecoveryIfAdministratorIsDemoted(t *testing.T) {
	alice := newAlice(t)
	carol := approved(t, alice)
	bob := approved(t, alice)
	if err := alice.SetAdmin(bg, mustMember(t, alice, carol).DeviceID, true); err != nil {
		t.Fatal(err)
	}
	aliceID := mustMember(t, carol, alice).DeviceID
	bobID := mustMember(t, alice, bob).DeviceID
	base := alice.Storage
	alice.Storage = storagetest.Wrap(base, storagetest.Hooks{
		Publish: func(ctx context.Context, next storage.Store, object storage.Object) error {
			if object.Kind == storage.KindControl {
				if err := bob.AddSecret(ctx, "default", "LATEST", "bob"); err != nil {
					return err
				}
			}
			return next.Publish(ctx, object)
		},
	})
	removal := alice.RemoveMember(bg, bobID)
	if !apperr.Is(removal, apperr.CodeRemovalWriteRace) {
		t.Fatalf("removal result: %v", removal)
	}
	resource, revision, _ := strings.Cut(apperr.PayloadOf(removal).Params["targets"], " ")

	preview, err := alice.ReviewRemovedRevision(bg, resource, revision, "")
	if err != nil {
		t.Fatal(err)
	}
	demoted := false
	alice.Storage = storagetest.Wrap(base, storagetest.Hooks{
		OpenPayload: func(ctx context.Context, next storage.Store, kind storage.Kind, scope string, rev digest.Digest) (io.ReadCloser, error) {
			if !demoted {
				demoted = true
				if err := carol.SetAdmin(ctx, aliceID, false); err != nil {
					return nil, err
				}
			}
			return next.OpenPayload(ctx, kind, scope, rev)
		},
	})
	if _, err := alice.ReviewRemovedRevision(bg, resource, revision, preview.Baseline); !apperr.Is(err, apperr.CodeRecoveryPreviewChanged) || !errors.Is(err, errControlMoved) {
		t.Fatalf("recovery after demotion: %v", err)
	}
	if !demoted || listOK(t, carol)["LATEST"] != "" {
		t.Fatal("the demoted administrator published a recovery")
	}
	alice.Storage = base
	if _, err := alice.ReviewRemovedRevision(bg, resource, revision, preview.Baseline); !apperr.Is(err, apperr.CodeAccessDenied) {
		t.Fatalf("recovery by a member: %v", err)
	}
	preview, err = carol.ReviewRemovedRevision(bg, resource, revision, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := carol.ReviewRemovedRevision(bg, resource, revision, preview.Baseline); err != nil {
		t.Fatal(err)
	}
	if got := listOK(t, alice)["LATEST"]; got != "bob" {
		t.Fatalf("recovery was not published to other devices: %q", got)
	}
}

func TestReviewRemovedRevisionRecoversAllReportedResources(t *testing.T) {
	alice := newAlice(t)
	bob := approved(t, alice)
	if err := bob.CreateEnvironment("qa"); err != nil {
		t.Fatal(err)
	}
	if err := bob.AddSecret(bg, "qa", "BASE", "qa"); err != nil {
		t.Fatal(err)
	}
	cfg, err := bob.loadProject()
	if err != nil {
		t.Fatal(err)
	}
	bobID := mustMember(t, alice, bob).DeviceID
	base := alice.Storage
	alice.Storage = storagetest.Wrap(base, storagetest.Hooks{
		Publish: func(ctx context.Context, next storage.Store, object storage.Object) error {
			if object.Kind == storage.KindControl {
				for _, env := range []string{"default", "qa"} {
					if err := bob.AddSecret(ctx, env, "LATEST", "bob"); err != nil {
						return err
					}
				}
			}
			return next.Publish(ctx, object)
		},
	})
	removal := alice.RemoveMember(bg, bobID)
	if !apperr.Is(removal, apperr.CodeRemovalWriteRace) {
		t.Fatalf("removal result: %v", removal)
	}
	lines := strings.Split(apperr.PayloadOf(removal).Params["targets"], "\n")
	if len(lines) != 2 {
		t.Fatalf("recovery targets: %v", lines)
	}
	alice.Storage = base
	if err := alice.AddSecret(bg, "default", "LATEST", "different"); err != nil {
		t.Fatal(err)
	}
	for _, line := range lines {
		resource, revision, _ := strings.Cut(line, " ")
		if resource == cfg.Resource("default") {
			preview, err := alice.ReviewRemovedRevision(bg, resource, revision, "")
			if err != nil || !slices.Equal(preview.Kept, []string{"LATEST"}) || len(preview.Diff.Added) != 0 {
				t.Fatalf("conflicting revision preview: %+v, %v", preview, err)
			}
			if _, err := alice.ReviewRemovedRevision(bg, resource, revision, preview.Baseline); err != nil {
				t.Fatal(err)
			}
			if got := listOK(t, alice)["LATEST"]; got != "different" {
				t.Fatalf("preview changed the current value: %q", got)
			}
			continue
		}
		if resource != cfg.Resource("qa") {
			t.Fatalf("unexpected resource: %q", resource)
		}
		preview, err := alice.ReviewRemovedRevision(bg, resource, revision, "")
		if err != nil || !slices.Equal(preview.Diff.Added, []string{"LATEST"}) {
			t.Fatalf("preview in unlisted environment: %+v, %v", preview, err)
		}
		if _, err := alice.ReviewRemovedRevision(bg, resource, revision, preview.Baseline); err != nil {
			t.Fatalf("recovery in unlisted environment: %v", err)
		}
	}
}

func TestRemovalReadFailureReportsIncompleteReEncryption(t *testing.T) {
	alice := newAlice(t)
	bob := approved(t, alice)
	target := mustMember(t, alice, bob).DeviceID
	var committed bool
	alice.Storage = storagetest.Wrap(alice.Storage, storagetest.Hooks{
		Publish: func(ctx context.Context, next storage.Store, object storage.Object) error {
			err := next.Publish(ctx, object)
			if err == nil && object.Kind == storage.KindControl {
				committed = true
			}
			return err
		},
		Discover: func(ctx context.Context, next storage.Store, kind storage.Kind, scope string) ([]digest.Digest, error) {
			if committed && kind == storage.KindState {
				return nil, io.ErrUnexpectedEOF
			}
			return next.Discover(ctx, kind, scope)
		},
	})
	err := alice.RemoveMember(bg, target)
	if !committed || !apperr.Is(err, apperr.CodeReencryptIncomplete) || !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("partial removal: committed=%t, error=%v", committed, err)
	}
}

func TestRemoveMemberRejectsUnavailableRevisionMetadata(t *testing.T) {
	alice := newAlice(t)
	bob := approved(t, alice)
	target := mustMember(t, alice, bob).DeviceID
	if err := bob.AddSecret(bg, "default", "LATEST", "bob"); err != nil {
		t.Fatal(err)
	}
	s, err := bob.openSession(bg)
	if err != nil {
		t.Fatal(err)
	}
	view, err := s.loadResource(bg, s.resource("default"))
	s.Close()
	if err != nil || len(view.Heads) != 1 {
		t.Fatalf("read Bob's head: %v", err)
	}
	base := alice.Storage
	for _, failure := range []error{storage.ErrNotFound, storage.ErrCorrupt} {
		t.Run(failure.Error(), func(t *testing.T) {
			latest := view.Heads[0].Digest
			alice.Storage = storagetest.Wrap(base, storagetest.Hooks{
				FetchHead: func(ctx context.Context, next storage.Store, kind storage.Kind, scope string, rev digest.Digest) ([]byte, error) {
					if kind == storage.KindState && rev == latest {
						return nil, failure
					}
					return next.FetchHead(ctx, kind, scope, rev)
				},
			})
			if err := alice.RemoveMember(bg, target); !apperr.Is(err, apperr.CodeUntrusted) {
				t.Fatalf("removing a member after failing to fetch a listed revision: %v", err)
			}
			alice.Storage = storagetest.Wrap(alice.Storage, storagetest.Hooks{
				Discover: func(ctx context.Context, next storage.Store, kind storage.Kind, scope string) ([]digest.Digest, error) {
					if kind == storage.KindCompaction {
						t.Error("ordinary secret read looked up compactions for unverified metadata")
						return nil, errors.New("compaction lookup unavailable")
					}
					return next.Discover(ctx, kind, scope)
				},
			})
			got, err := alice.ListSecrets(bg, "default")
			if err != nil || got["KEY"] != "v1" {
				t.Fatalf("ordinary read result = %v, %v", got, err)
			}

			_ = mustMember(t, alice, bob)
		})
	}
}

func TestRemoveMemberRechecksControlAfterAcceptingStates(t *testing.T) {
	alice := newAlice(t)
	bob := approved(t, alice)
	aliceID := mustMember(t, alice, alice).DeviceID
	bobID := mustMember(t, alice, bob).DeviceID
	if err := alice.SetAdmin(bg, bobID, true); err != nil {
		t.Fatal(err)
	}
	if err := bob.AddSecret(bg, "default", "LATEST", "bob"); err != nil {
		t.Fatal(err)
	}
	demoted := false
	alice.Storage = storagetest.Wrap(alice.Storage, storagetest.Hooks{
		OpenPayload: func(ctx context.Context, next storage.Store, kind storage.Kind, scope string, rev digest.Digest) (io.ReadCloser, error) {
			if !demoted {
				demoted = true
				if err := bob.SetAdmin(ctx, aliceID, false); err != nil {
					return nil, err
				}
			}
			return next.OpenPayload(ctx, kind, scope, rev)
		},
	})
	if err := alice.RemoveMember(bg, bobID); !apperr.Is(err, apperr.CodeConflict) {
		t.Fatalf("removal did not detect changed Control: %v", err)
	}
	if got := mustMember(t, alice, alice); got.Admin {
		t.Fatalf("demotion did not remain the current Control: %+v", got)
	}
	_ = mustMember(t, alice, bob)
}

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
	m, err := a.ListMembers(bg)
	if err != nil || len(m) == 0 {
		t.Fatal(err)
	}
	return m[0].Recipient
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
	vs, err := createSigner(victim, ws)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = vs.Close() }()
	id, _, _, err := victim.Identities.Create(ws)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = id.Close() }()
	other, err := wsp.NewJoinRequest("0192f3a0-7c1e-7a55-9d3c-000000000000", id.Identity.Recipient().String(), time.Now(), vs)
	if err != nil {
		t.Fatal(err)
	}
	plant(other)
	good, err := wsp.NewJoinRequest(ws, id.Identity.Recipient().String(), time.Now(), vs)
	if err != nil {
		t.Fatal(err)
	}
	signed, _ := wsp.DecodeSigned(good)
	ms, _ := loadSigner(mallory, ws)
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
	ms, _ := loadSigner(mallory, mustWorkspace(t, mallory))
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
// was written under, not by who is a member now. The removal takes it over even
// though the environment is missing from the admin's enbu.toml: re-encryption
// finds it in storage and publishes it again under the new member list.
func TestHistoricalStateOfARemovedAuthorStillVerifies(t *testing.T) {
	alice := newEmptyAlice(t)
	bob := approved(t, alice)
	bs, err := bob.openSession(bg)
	if err != nil {
		t.Fatal(err)
	}
	defer bs.Close()
	bobsEnv := "staging"
	bobsState, err := bs.writeState(bg, bs.resource(bobsEnv), map[string]string{"A": "by bob"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	bobsRev := bobsState.Digest
	if err := alice.RemoveMember(bg, mustMember(t, alice, bob).DeviceID); err != nil {
		t.Fatal(err)
	}
	as, err := alice.openSession(bg)
	if err != nil {
		t.Fatal(err)
	}
	defer as.Close()
	read, err := as.readResource(bg, as.resource(bobsEnv), nil, true)
	if err != nil || read.secrets["A"] != "by bob" || len(read.heads) != 1 || read.heads[0].Author != as.self() {
		t.Fatalf("the removal did not take over the environment: %+v %v", read, err)
	}
	sv, err := as.loadResource(bg, as.resource(bobsEnv))
	if err != nil || len(sv.States) != 2 || sv.States[bobsRev] == nil {
		t.Fatalf("history by a removed author: %v", err)
	}
	secrets, err := as.decrypt(bg, sv.States[bobsRev]) // alice could decrypt it: she was a recipient then
	if err != nil || secrets["A"] != "by bob" {
		t.Fatalf("secrets = %v %v", secrets, err)
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
