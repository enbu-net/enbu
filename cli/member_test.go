package cli

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/enbu-net/enbu/app"
)

// newJoiner is another machine of the same repository: same storage and the
// committed enbu.toml, its own keys.
func newJoiner(t *testing.T, founder *app.App) *app.App {
	t.Helper()
	dir := t.TempDir()
	shared, err := os.ReadFile(filepath.Join(founder.RepositoryDir, "enbu.toml"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "enbu.toml"), shared, 0o644); err != nil {
		t.Fatal(err)
	}
	return &app.App{Storage: founder.Storage, TokenProvider: &deleteTestTokenProvider{}, RepoDetector: &deleteTestRepoDetector{},
		Identities: &staticKeyStore{}, RepositoryDir: dir, CheckpointDir: t.TempDir()}
}

func list(t *testing.T, a *app.App, args ...string) []any {
	t.Helper()
	env := executeJSON(t, NewWithApp("test", a), args...)
	data := objectField(t, env, "data")
	key := args[1]
	if key == "list" {
		key = "members"
	}
	items, _ := data[key].([]any)
	return items
}

func TestMemberApproveFlow(t *testing.T) {
	alice, _ := newSeededApp(t, map[string]string{"KEY": "value"})
	bob := newJoiner(t, alice)
	res, err := bob.InitializeRepository(context.Background())
	if err != nil || !res.Pending {
		t.Fatalf("join: %+v %v", res, err)
	}

	requests := list(t, alice, "member", "requests", "--json")
	if len(requests) != 1 || requests[0].(map[string]any)["device_id"] != res.DeviceID {
		t.Fatalf("requests = %v", requests)
	}
	// The fingerprint a person reads aloud is enough to pick the device.
	approved := executeJSON(t, NewWithApp("test", alice), "member", "approve", "--device", res.Fingerprint, "--json")
	if got := stringField(t, objectField(t, approved, "data"), "action"); got != "approve" {
		t.Fatalf("action = %q", got)
	}
	if left := list(t, alice, "member", "requests", "--json"); len(left) != 0 {
		t.Fatalf("approved request still listed: %v", left)
	}
	if members := list(t, alice, "member", "list", "--json"); len(members) != 2 {
		t.Fatalf("members = %v", members)
	}
	if got := secretsOf(t, bob); got["KEY"] != "value" {
		t.Fatalf("approved device cannot read: %v", got)
	}

	executeJSON(t, NewWithApp("test", alice), "member", "remove", "--device", res.DeviceID, "--json")
	if _, err := bob.ListSecrets(context.Background(), "default"); err == nil {
		t.Fatal("removed device still reads secrets")
	}
}

func TestMemberCommandsNeedExplicitDeviceWithoutTerminal(t *testing.T) {
	alice, _ := newSeededApp(t, nil)
	for i := 0; i < 2; i++ {
		b := newJoiner(t, alice)
		if _, err := b.InitializeRepository(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	// Two candidates and no terminal: refuse rather than guess.
	cmd := NewWithApp("test", alice)
	cmd.SetArgs([]string{"member", "approve", "--json"})
	if err := cmd.Execute(); err == nil {
		t.Fatal("approved without choosing a device")
	}
	if left := list(t, alice, "member", "requests", "--json"); len(left) != 2 {
		t.Fatalf("a request was approved implicitly: %v", left)
	}
	cmd = NewWithApp("test", alice)
	cmd.SetArgs([]string{"member", "approve", "--device", "0000-0000-0000-0000-0000", "--json"})
	if err := cmd.Execute(); err == nil {
		t.Fatal("approved a device that never asked")
	}
}

func TestMemberRemoveLastAdminFails(t *testing.T) {
	alice, _ := newSeededApp(t, nil)
	members := list(t, alice, "member", "list", "--json")
	id := members[0].(map[string]any)["device_id"].(string)
	cmd := NewWithApp("test", alice)
	cmd.SetArgs([]string{"member", "remove", "--device", id, "--json"})
	if err := cmd.Execute(); err == nil {
		t.Fatal("removed the only admin")
	}
}
