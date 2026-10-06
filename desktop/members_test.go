package desktop

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/enbu-net/enbu/app"
	"github.com/enbu-net/enbu/app/apptest"
	"github.com/enbu-net/enbu/pkg/apperr"
	"github.com/enbu-net/enbu/pkg/config"
	"github.com/enbu-net/enbu/pkg/signing"
	"github.com/enbu-net/enbu/pkg/storage"
)

// membersFixture is a workspace on local storage with one founder (alice) and a
// second device (bob) that shares her enbu.toml, as it would through the repository.
type membersFixture struct {
	alice, bob *Service
	store      *storage.Store
	workspace  string
	bobDevice  string
}

func newMembersFixture(t *testing.T) *membersFixture {
	t.Helper()
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	t.Setenv("GITHUB_TOKEN", "")
	storageDir := t.TempDir()
	cfg := config.NewProjectWithEnvironment("default")
	cfg.Storage = config.StorageConfig{URL: "local:///" + strings.TrimPrefix(filepath.ToSlash(storageDir), "/")}
	newService := func(dir string) (*Service, *app.App) {
		if err := config.SaveProjectTo(dir, cfg); err != nil {
			t.Fatal(err)
		}
		a := app.New()
		a.Identities = &desktopKeyStore{values: map[string][]byte{}}
		a.CheckpointDir = t.TempDir()
		s := NewService(a)
		s.repoPath = dir
		return s, a
	}
	ctx := context.Background()
	aliceDir := t.TempDir()
	alice, aliceApp := newService(aliceDir)
	store := storage.NewLocal(storageDir)
	ref, err := store.Blobs.Put(ctx, strings.NewReader(cfg.WorkspaceID))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Refs.Put(ctx, "enbu-workspace", ref, ""); err != nil {
		t.Fatal(err)
	}
	if err := apptest.Control(ctx, store, aliceDir, aliceApp.Identities); err != nil {
		t.Fatal(err)
	}
	// The repository now carries the trusted genesis; bob receives it with enbu.toml.
	shared, err := os.ReadFile(filepath.Join(aliceDir, "enbu.toml"))
	if err != nil {
		t.Fatal(err)
	}
	bobDir := t.TempDir()
	bob, bobApp := newService(bobDir)
	if err := os.WriteFile(filepath.Join(bobDir, "enbu.toml"), shared, 0o644); err != nil {
		t.Fatal(err)
	}
	device, err := apptest.JoinRequest(ctx, store, cfg.WorkspaceID, bobApp.Identities)
	if err != nil {
		t.Fatal(err)
	}
	return &membersFixture{alice: alice, bob: bob, store: store, workspace: cfg.WorkspaceID, bobDevice: device}
}

// another asks to join with a fresh device, the way a third person would.
func (f *membersFixture) another(t *testing.T) string {
	t.Helper()
	id, err := apptest.JoinRequest(context.Background(), f.store, f.workspace, &desktopKeyStore{values: map[string][]byte{}})
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func TestMembersApprovalFlow(t *testing.T) {
	f := newMembersFixture(t)
	requests, err := f.alice.ListJoinRequests()
	if err != nil || len(requests) != 1 || requests[0].DeviceID != f.bobDevice || requests[0].Fingerprint != signing.DeviceID(f.bobDevice).Fingerprint() {
		t.Fatalf("requests: %+v %v", requests, err)
	}
	if err := f.alice.ApproveMember(f.bobDevice); err != nil {
		t.Fatal(err)
	}
	// The request was consumed by the approval.
	if requests, err = f.alice.ListJoinRequests(); err != nil || len(requests) != 0 {
		t.Fatalf("requests after approval: %+v %v", requests, err)
	}
	members, err := f.alice.ListMembers()
	if err != nil || len(members) != 2 {
		t.Fatalf("members: %+v %v", members, err)
	}
	var self, admins int
	for _, m := range members {
		if m.Self {
			self++
		}
		if m.Admin {
			admins++
		}
	}
	if self != 1 || admins != 1 {
		t.Fatalf("flags: %+v", members)
	}
	if err := f.alice.RemoveMember(f.bobDevice); err != nil {
		t.Fatal(err)
	}
	if members, _ = f.alice.ListMembers(); len(members) != 1 {
		t.Fatalf("after removal: %+v", members)
	}
}

func TestApprovingAnUnknownOrMalformedDeviceFails(t *testing.T) {
	f := newMembersFixture(t)
	for name, id := range map[string]string{
		"never asked": strings.Repeat("a", 64),
		"empty":       "",
		"too short":   "abcd",
		"not hex":     strings.Repeat("z", 64),
		"upper case":  strings.Repeat("A", 64),
	} {
		t.Run(name, func(t *testing.T) {
			if err := f.alice.ApproveMember(id); err == nil {
				t.Fatalf("approved %q", id)
			}
		})
	}
	if members, _ := f.alice.ListMembers(); len(members) != 1 {
		t.Fatalf("membership changed: %+v", members)
	}
}

func TestRemovingTheLastAdminOrAStrangerFails(t *testing.T) {
	f := newMembersFixture(t)
	members, err := f.alice.ListMembers()
	if err != nil || len(members) != 1 {
		t.Fatalf("members: %+v %v", members, err)
	}
	if err := f.alice.RemoveMember(members[0].DeviceID); !apperr.Is(err, apperr.CodeInvalidArgument) {
		t.Fatalf("removing the last admin: %v", err)
	}
	if err := f.alice.RemoveMember(strings.Repeat("b", 64)); !apperr.Is(err, apperr.CodeInvalidArgument) {
		t.Fatalf("removing a stranger: %v", err)
	}
	if err := f.alice.RemoveMember(""); err == nil {
		t.Fatal("removed an empty device id")
	}
}

func TestOnlyAnAdminCanChangeMembers(t *testing.T) {
	f := newMembersFixture(t)
	if err := f.alice.ApproveMember(f.bobDevice); err != nil {
		t.Fatal(err)
	}
	carol := f.another(t)
	// Bob is a member, not an admin.
	if err := f.bob.ApproveMember(carol); !apperr.Is(err, apperr.CodeAccessDenied) {
		t.Fatalf("a member approved a device: %v", err)
	}
	if err := f.bob.RemoveMember(f.bobDevice); !apperr.Is(err, apperr.CodeAccessDenied) {
		t.Fatalf("a member removed a device: %v", err)
	}
	members, err := f.alice.ListMembers()
	if err != nil || len(members) != 2 {
		t.Fatalf("members: %+v %v", members, err)
	}
	// Bob still sees the list; only changing it needs the admin right.
	if seen, err := f.bob.ListMembers(); err != nil || len(seen) != 2 {
		t.Fatalf("a member cannot see the members: %+v %v", seen, err)
	}
}
