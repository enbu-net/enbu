package cli

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/enbu-net/enbu/app"
	"github.com/enbu-net/enbu/app/apptest"
	"github.com/enbu-net/enbu/pkg/signing"
	"github.com/spf13/cobra"
)

// newFounder is a bootstrapped workspace whose only member is the test app.
func newFounder(t *testing.T) *app.App {
	t.Helper()
	a, _ := newSeededApp(t, map[string]string{"KEY": "value"})
	// A no-op when the workspace was initialized through the real flow.
	if err := apptest.Control(context.Background(), a.Storage, a.RepositoryDir, a.Identities); err != nil {
		t.Fatal(err)
	}
	return a
}

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

// requestJoin leaves a join request the way `enbu init` does for a new device.
func requestJoin(t *testing.T, b *app.App) (deviceID, fingerprint string) {
	t.Helper()
	id, err := apptest.JoinRequest(context.Background(), b.Storage, testWorkspaceID, b.Identities)
	if err != nil {
		t.Fatal(err)
	}
	return id, signing.DeviceID(id).Fingerprint()
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
	alice := newFounder(t)
	bob := newJoiner(t, alice)
	deviceID, fingerprint := requestJoin(t, bob)

	requests := list(t, alice, "member", "requests", "--json")
	if len(requests) != 1 || requests[0].(map[string]any)["device_id"] != deviceID {
		t.Fatalf("requests = %v", requests)
	}
	// The fingerprint a person reads aloud is enough to pick the device.
	approved := executeJSON(t, NewWithApp("test", alice), "member", "approve", "--device", fingerprint, "--json")
	if got := stringField(t, objectField(t, approved, "data"), "action"); got != "approve" {
		t.Fatalf("action = %q", got)
	}
	if left := list(t, alice, "member", "requests", "--json"); len(left) != 0 {
		t.Fatalf("approved request still listed: %v", left)
	}
	if members := list(t, alice, "member", "list", "--json"); len(members) != 2 {
		t.Fatalf("members = %v", members)
	}

	executeJSON(t, NewWithApp("test", alice), "member", "remove", "--device", deviceID, "--json")
	if members := list(t, alice, "member", "list", "--json"); len(members) != 1 {
		t.Fatalf("members after removal = %v", members)
	}
}

func TestMemberCommandsNeedExplicitDeviceWithoutTerminal(t *testing.T) {
	alice := newFounder(t)
	for i := 0; i < 2; i++ {
		requestJoin(t, newJoiner(t, alice))
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
	alice := newFounder(t)
	members := list(t, alice, "member", "list", "--json")
	id := members[0].(map[string]any)["device_id"].(string)
	cmd := NewWithApp("test", alice)
	cmd.SetArgs([]string{"member", "remove", "--device", id, "--json"})
	if err := cmd.Execute(); err == nil {
		t.Fatal("removed the only admin")
	}
}

func TestMemberAdminGrantAndRevoke(t *testing.T) {
	alice := newFounder(t)
	bob := newJoiner(t, alice)
	deviceID, _ := requestJoin(t, bob)
	executeJSON(t, NewWithApp("test", alice), "member", "approve", "--device", deviceID, "--json")

	adminOf := func() bool {
		for _, m := range list(t, alice, "member", "list", "--json") {
			if m.(map[string]any)["device_id"] == deviceID {
				return m.(map[string]any)["admin"] == true
			}
		}
		t.Fatal("device is not a member")
		return false
	}
	executeJSON(t, NewWithApp("test", alice), "member", "admin", "--device", deviceID, "--json")
	if !adminOf() {
		t.Fatal("grant did not make the device an admin")
	}
	executeJSON(t, NewWithApp("test", alice), "member", "admin", "--device", deviceID, "--revoke", "--json")
	if adminOf() {
		t.Fatal("revoke did not remove the admin right")
	}
	// The workspace always keeps one admin.
	self := list(t, alice, "member", "list", "--json")[0].(map[string]any)
	for _, m := range list(t, alice, "member", "list", "--json") {
		if m.(map[string]any)["self"] == true {
			self = m.(map[string]any)
		}
	}
	cmd := NewWithApp("test", alice)
	cmd.SetArgs([]string{"member", "admin", "--device", self["device_id"].(string), "--revoke", "--json"})
	if err := cmd.Execute(); err == nil {
		t.Fatal("the last admin was demoted")
	}
}

// withTerminal makes the prompts believe stdio is a terminal and answers them.
func withTerminal(t *testing.T, answer string) func(*cobra.Command) {
	t.Helper()
	old := stdioIsTerminal
	stdioIsTerminal = func() bool { return true }
	t.Cleanup(func() { stdioIsTerminal = old })
	return func(c *cobra.Command) { c.SetIn(strings.NewReader(answer)) }
}

func TestApproveAsksToCompareTheFingerprint(t *testing.T) {
	for name, tc := range map[string]struct {
		answer   string
		approved bool
	}{
		"yes":          {"y\n", true},
		"full yes":     {"YES\n", true},
		"no":           {"n\n", false},
		"just enter":   {"\n", false},
		"end of input": {"", false},
		"anything":     {"sure\n", false},
	} {
		t.Run(name, func(t *testing.T) {
			alice := newFounder(t)
			requestJoin(t, newJoiner(t, alice))
			in := withTerminal(t, tc.answer)
			cmd := NewWithApp("test", alice)
			in(cmd)
			cmd.SetArgs([]string{"member", "approve"}) // a single candidate skips the list
			err := cmd.Execute()
			members := len(list(t, alice, "member", "list", "--json"))
			if tc.approved && (err != nil || members != 2) {
				t.Fatalf("approval refused: %v (%d members)", err, members)
			}
			if !tc.approved && (err == nil || members != 1) {
				t.Fatalf("approved without confirmation: %v (%d members)", err, members)
			}
		})
	}
}

func TestYesSkipsTheConfirmationButNotTheChoice(t *testing.T) {
	alice := newFounder(t)
	requestJoin(t, newJoiner(t, alice))
	in := withTerminal(t, "") // no answer is ever given
	cmd := NewWithApp("test", alice)
	in(cmd)
	cmd.SetArgs([]string{"member", "approve", "--yes"})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	if got := len(list(t, alice, "member", "list", "--json")); got != 2 {
		t.Fatalf("members = %d", got)
	}
}

func TestExplicitDeviceNeedsNoPrompt(t *testing.T) {
	alice := newFounder(t)
	id, _ := requestJoin(t, newJoiner(t, alice))
	in := withTerminal(t, "")
	cmd := NewWithApp("test", alice)
	in(cmd)
	cmd.SetArgs([]string{"member", "approve", "--device", id})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("naming the device is the decision: %v", err)
	}
}

func TestGrantingAdminAsksForConfirmation(t *testing.T) {
	alice := newFounder(t)
	bob := newJoiner(t, alice)
	id, _ := requestJoin(t, bob)
	executeJSON(t, NewWithApp("test", alice), "member", "approve", "--device", id, "--json")
	in := withTerminal(t, "n\n")
	cmd := NewWithApp("test", alice)
	in(cmd)
	cmd.SetArgs([]string{"member", "admin"}) // bob is the only other member
	if err := cmd.Execute(); err == nil {
		t.Fatal("an admin was granted without confirmation")
	}
	for _, m := range list(t, alice, "member", "list", "--json") {
		if m.(map[string]any)["device_id"] == id && m.(map[string]any)["admin"] == true {
			t.Fatal("the device became an admin anyway")
		}
	}
}
