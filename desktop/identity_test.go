package desktop

import (
	"testing"

	"github.com/enbu-net/enbu/app"
	"github.com/enbu-net/enbu/pkg/apperr"
)

func TestImportSecretsFromDotenvContent(t *testing.T) {
	f := newMembersFixture(t)
	envs, err := f.alice.ListEnvironments()
	if err != nil || len(envs) != 1 {
		t.Fatalf("listing environments: %v %v", envs, err)
	}
	target := app.EnvironmentTarget{WorkspaceID: f.workspace, Environment: "default", Incarnation: envs[0].Incarnation}
	for _, stale := range []struct {
		path   string
		target app.EnvironmentTarget
	}{
		{f.bob.repoPath, target},
		{f.alice.repoPath, app.EnvironmentTarget{WorkspaceID: "different", Environment: "default", Incarnation: target.Incarnation}},
		{f.alice.repoPath, app.EnvironmentTarget{WorkspaceID: f.workspace, Environment: "default", Incarnation: "replaced"}},
	} {
		if _, err := f.alice.ImportSecrets(stale.path, stale.target, "LEAK=value\n", false); !apperr.Is(err, apperr.CodeConflict) {
			t.Fatalf("stale import: %v", err)
		}
	}
	result, err := f.alice.ImportSecrets(f.alice.repoPath, target, "A=1\nB=2\n", false)
	if err != nil || len(result.Added) != 2 || result.Environment != "default" {
		t.Fatalf("import: %+v %v", result, err)
	}
	// Another value stops the import unless overwrite is set, as with --overwrite.
	if _, err := f.alice.ImportSecrets(f.alice.repoPath, target, "A=changed\nB=2\n", false); !apperr.Is(err, apperr.CodeSecretExists) {
		t.Fatalf("changed value without overwrite: %v", err)
	}
	result, err = f.alice.ImportSecrets(f.alice.repoPath, target, "A=changed\nB=2\n", true)
	if err != nil || len(result.Updated) != 1 || len(result.Unchanged) != 1 {
		t.Fatalf("overwrite: %+v %v", result, err)
	}
	if _, err := f.alice.ImportSecrets(f.alice.repoPath, target, "not dotenv", false); !apperr.Is(err, apperr.CodeInvalidArgument) {
		t.Fatalf("invalid content: %v", err)
	}
}

func TestGetWorkspaceRejectsAStaleRepository(t *testing.T) {
	f := newMembersFixture(t)
	if _, err := f.alice.GetWorkspace(f.bob.repoPath); !apperr.Is(err, apperr.CodeConflict) {
		t.Fatalf("stale repository read: %v", err)
	}
	if err := f.alice.AddSecret("default", "KEY", "value"); err != nil {
		t.Fatal(err)
	}
	snapshot, err := f.alice.GetWorkspace(f.alice.repoPath)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.WorkspaceID != f.workspace || len(snapshot.Environments) != 1 ||
		!snapshot.Environments[0].IsCurrent || snapshot.Environments[0].Name != snapshot.Secrets.Environment ||
		len(snapshot.Secrets.Secrets) != 1 || snapshot.Secrets.Secrets[0].Key != "KEY" || snapshot.Conflicts != nil {
		t.Fatalf("inconsistent workspace snapshot: %+v", snapshot)
	}
}

func TestRestoreHistoryRejectsAStaleCheckoutOfTheSameWorkspace(t *testing.T) {
	f := newMembersFixture(t)
	if err := f.alice.AddSecret("default", "KEY", "before"); err != nil {
		t.Fatal(err)
	}
	if err := f.alice.EditSecret("default", "KEY", "after"); err != nil {
		t.Fatal(err)
	}
	entries, err := f.alice.ListHistory("default")
	if err != nil || len(entries) != 2 {
		t.Fatalf("listing revisions: %+v, %v", entries, err)
	}
	envs, err := f.alice.ListEnvironments()
	if err != nil || len(envs) != 1 {
		t.Fatalf("listing environments: %+v, %v", envs, err)
	}
	target := app.EnvironmentTarget{WorkspaceID: f.workspace, Environment: "default", Incarnation: envs[0].Incarnation}
	if err := f.alice.RestoreHistory(f.bob.repoPath, target, entries[0].Tag); !apperr.Is(err, apperr.CodeConflict) {
		t.Fatalf("restore with a stale checkout: %v", err)
	}
	current, err := f.alice.ListSecrets("default")
	if err != nil || len(current.Secrets) != 1 || current.Secrets[0].Value != "after" {
		t.Fatalf("current value after stale restore: %+v, %v", current, err)
	}
	if err := f.alice.RestoreHistory(f.alice.repoPath, target, entries[0].Tag); err != nil {
		t.Fatalf("restore with the selected checkout: %v", err)
	}
}

func TestSetAdminGrantsAndRevokes(t *testing.T) {
	f := newMembersFixture(t)
	if err := f.alice.ApproveMember(f.bobDevice); err != nil {
		t.Fatal(err)
	}
	if err := f.alice.SetAdmin(f.bobDevice, true); err != nil {
		t.Fatal(err)
	}
	if !isAdmin(t, f.alice, f.bobDevice) {
		t.Fatal("bob is not an admin after the grant")
	}
	if err := f.bob.SetAdmin(f.bobDevice, false); err != nil {
		t.Fatal(err)
	}
	if isAdmin(t, f.alice, f.bobDevice) {
		t.Fatal("bob is still an admin after the revoke")
	}
	if err := f.bob.SetAdmin(f.bobDevice, true); !apperr.Is(err, apperr.CodeAccessDenied) {
		t.Fatalf("a member made itself an admin: %v", err)
	}
}

func isAdmin(t *testing.T, s *Service, device string) bool {
	t.Helper()
	members, err := s.ListMembers()
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range members {
		if m.DeviceID == device {
			return m.Admin
		}
	}
	t.Fatalf("%s is not a member", device)
	return false
}

func TestGetIdentityDescribesThisDevice(t *testing.T) {
	f := newMembersFixture(t)
	info, err := f.alice.GetIdentity()
	if err != nil || info.Recipient == "" || info.Fingerprint == "" {
		t.Fatalf("identity: %+v %v", info, err)
	}
	members, err := f.alice.ListMembers()
	if err != nil || len(members) != 1 || members[0].Fingerprint != info.Fingerprint || !members[0].Self {
		t.Fatalf("members: %+v %v", members, err)
	}
}
