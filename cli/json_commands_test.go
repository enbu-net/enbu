package cli

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/enbu-net/enbu/app"
	"github.com/enbu-net/enbu/pkg/provider"
	gitprovider "github.com/enbu-net/enbu/pkg/provider/git"
	"github.com/enbu-net/enbu/pkg/storage"
	"github.com/enbu-net/enbu/pkg/storage/storagetest"
)

func TestJSONSecretCommands(t *testing.T) {
	tests := []struct {
		name    string
		command string
		initial map[string]string
		args    []string
		secrets []string
	}{
		{name: "add", command: "add", initial: nil, args: []string{"API_KEY", "secret"}, secrets: []string{"secret"}},
		{name: "edit", command: "edit", initial: map[string]string{"API_KEY": "old"}, args: []string{"API_KEY", "new"}, secrets: []string{"old", "new"}},
		{name: "delete", command: "delete", initial: map[string]string{"API_KEY": "secret"}, args: []string{"API_KEY"}, secrets: []string{"secret"}},
		{name: "sync", command: "sync", initial: map[string]string{"API_KEY": "secret"}, secrets: []string{"secret"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a, _ := newSeededApp(t, tt.initial)
			commandArgs := append([]string{tt.command, "--json"}, tt.args...)
			envelope := executeJSON(t, NewWithApp("test", a), commandArgs...)
			data := objectField(t, envelope, "data")
			if got := stringField(t, data, "action"); got != tt.command {
				t.Fatalf("action = %q, want %q", got, tt.command)
			}
			if got := stringField(t, data, "environment"); got != app.DefaultEnvironment {
				t.Fatalf("environment = %q", got)
			}
			serialized := fmt.Sprint(envelope)
			for _, secret := range tt.secrets {
				if strings.Contains(serialized, secret) {
					t.Fatalf("secret value %q leaked in response: %#v", secret, envelope)
				}
			}
		})
	}
}

func TestJSONPullReturnsSecretsWithoutWritingFile(t *testing.T) {
	dir := enterTempRepository(t)
	a, _ := newSeededApp(t, map[string]string{
		"API_KEY":   "secret",
		"MULTILINE": "first\nsecond",
	})

	envelope := executeJSON(t, NewWithApp("test", a), "pull", "--json")
	data := objectField(t, envelope, "data")
	secrets := objectField(t, data, "secrets")
	if got := stringField(t, secrets, "MULTILINE"); got != "first\nsecond" {
		t.Fatalf("multiline secret = %q", got)
	}
	for _, d := range []string{dir, a.RepositoryDir} {
		if _, err := os.Stat(filepath.Join(d, ".env")); !os.IsNotExist(err) {
			t.Fatalf("pull --json wrote .env in %s: %v", d, err)
		}
	}
}

func TestJSONSwitchOperations(t *testing.T) {
	enterTempRepository(t)
	a := &app.App{}

	create := executeJSON(t, NewWithApp("test", a), "switch", "--create", "staging", "--json")
	if got := stringField(t, objectField(t, create, "data"), "action"); got != "create" {
		t.Fatalf("create action = %q", got)
	}

	list := executeJSON(t, NewWithApp("test", a), "switch", "--list", "--json")
	data := objectField(t, list, "data")
	environments, ok := data["environments"].([]any)
	if !ok || len(environments) != 2 {
		t.Fatalf("environments = %#v", data["environments"])
	}

	switched := executeJSON(t, NewWithApp("test", a), "switch", "default", "--json")
	if got := stringField(t, objectField(t, switched, "data"), "action"); got != "switch" {
		t.Fatalf("switch action = %q", got)
	}

	renamed := executeJSON(t, NewWithApp("test", a), "switch", "--move", "staging", "stage", "--json")
	if got := stringField(t, objectField(t, renamed, "data"), "action"); got != "rename" {
		t.Fatalf("rename action = %q", got)
	}

	deleted := executeJSON(t, NewWithApp("test", a), "switch", "--delete", "stage", "--json")
	if got := stringField(t, objectField(t, deleted, "data"), "action"); got != "delete" {
		t.Fatalf("delete action = %q", got)
	}
}

func TestJSONHistoryCommands(t *testing.T) {
	enterTempRepository(t)
	a, _ := newSeededApp(t, nil)
	ctx := context.Background()
	// Each change leaves a signed history snapshot.
	for _, step := range []func() error{
		func() error { return a.AddSecret(ctx, "default", "A", "1") },
		func() error { return a.EditSecret(ctx, "default", "A", "2") },
		func() error { return a.AddSecret(ctx, "default", "B", "3") },
	} {
		if err := step(); err != nil {
			t.Fatal(err)
		}
	}

	list := executeJSON(t, NewWithApp("test", a), "history", "list", "--json")
	entries, ok := objectField(t, list, "data")["entries"].([]any)
	if !ok || len(entries) != 3 {
		t.Fatalf("entries = %#v", objectField(t, list, "data")["entries"])
	}

	diff := executeJSON(t, NewWithApp("test", a), "history", "diff", "2", "3", "--json")
	diffData := objectField(t, diff, "data")
	added, ok := diffData["added"].([]any)
	if !ok || len(added) != 1 || added[0] != "B" {
		t.Fatalf("added = %#v", diffData["added"])
	}

	restore := executeJSON(t, NewWithApp("test", a), "history", "restore", "1", "--json")
	if got := objectField(t, restore, "data")["version"]; got != float64(1) {
		t.Fatalf("version = %#v", got)
	}
	if got := secretsOf(t, a); !reflect.DeepEqual(got, map[string]string{"A": "1"}) {
		t.Fatalf("restored secrets = %v", got)
	}
}

func TestJSONInit(t *testing.T) {
	dir := t.TempDir()
	original, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(original) })
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}

	store := storagetest.NewMemory()
	a := &app.App{
		Storage:       store,
		TokenProvider: &deleteTestTokenProvider{},
		RepoDetector:  &deleteTestRepoDetector{},
		Identities:    &staticKeyStore{},
		Git:           &jsonInitGit{root: dir},
		Platform:      &jsonInitPlatform{},
	}
	envelope := executeJSON(t, NewWithApp("test", a), "init", "--json")
	data := objectField(t, envelope, "data")
	if got := stringField(t, data, "mode"); got != "initialize" {
		t.Fatalf("mode = %q", got)
	}
	if stringField(t, data, "public_key") == "" || stringField(t, data, "device_id") == "" || stringField(t, data, "fingerprint") == "" {
		t.Fatalf("missing key material in %v", data)
	}
	if data["pending"] != false {
		t.Fatalf("the founder must not be pending: %v", data["pending"])
	}
	// The workspace is rooted in a signed Control.
	if controls, err := store.Discover(context.Background(), storage.KindControl, ""); err != nil || len(controls) != 1 {
		t.Fatalf("controls: %v %v", controls, err)
	}
	content, err := os.ReadFile(filepath.Join(dir, "enbu.toml"))
	if err != nil || !strings.Contains(string(content), "control_genesis") {
		t.Fatalf("enbu.toml lacks the trusted genesis: %s %v", content, err)
	}
}

func TestJSONInitJoinWithoutIdentityUpdatesGitignore(t *testing.T) {
	dir := t.TempDir()
	original, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(original) })
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}

	// Another device already created the workspace and stored a secret. Its
	// enbu.toml, with the trusted genesis, is what the repository shares.
	store := storagetest.NewMemory()
	founder := &app.App{TokenProvider: &deleteTestTokenProvider{}, RepoDetector: &deleteTestRepoDetector{}, Identities: &staticKeyStore{}, RepositoryDir: t.TempDir()}
	bootstrapCLIApp(t, founder, store)
	if err := founder.AddSecret(context.Background(), "default", "KEY", "value"); err != nil {
		t.Fatal(err)
	}
	shared, err := os.ReadFile(filepath.Join(founder.RepositoryDir, "enbu.toml"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "enbu.toml"), shared, 0o644); err != nil {
		t.Fatal(err)
	}

	a := &app.App{
		Storage:       store,
		TokenProvider: &deleteTestTokenProvider{},
		RepoDetector:  &deleteTestRepoDetector{},
		Identities:    &staticKeyStore{},
		Git:           &jsonInitGit{root: dir},
		Platform:      &jsonInitPlatform{},
		CheckpointDir: t.TempDir(),
	}
	a.RepositoryDir = dir
	envelope := executeJSON(t, NewWithApp("test", a), "init", "--json")
	data := objectField(t, envelope, "data")
	if got := stringField(t, data, "mode"); got != "join" {
		t.Fatalf("mode = %q", got)
	}
	if data["pending"] != true {
		t.Fatalf("a new device must wait for approval: %v", data["pending"])
	}

	content, err := os.ReadFile(filepath.Join(dir, ".gitignore"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(content), ".env") {
		t.Fatalf(".gitignore does not contain .env: %q", content)
	}
}

func enterTempRepository(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	original, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(original) })
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	content := `version = "v1alpha2"
default_env = "default"

[env.default]
output = ".env"
`
	if err := os.WriteFile(filepath.Join(dir, "enbu.toml"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

type jsonInitGit struct {
	root string
}

func (g *jsonInitGit) Inspect(context.Context, string) (gitprovider.Repository, error) {
	return gitprovider.Repository{Root: g.root, HasGit: true}, nil
}

func (*jsonInitGit) Init(context.Context, string) error { return nil }

func (*jsonInitGit) AddRemote(context.Context, string, string, string) error { return nil }

func (*jsonInitGit) CommitFiles(context.Context, string, []string, string) error { return nil }

type jsonInitPlatform struct{}

func (*jsonInitPlatform) GetUser(context.Context) (*provider.User, error) {
	return &provider.User{ID: 1, Login: "alice"}, nil
}

func (*jsonInitPlatform) IsOrganization(context.Context, string) bool { return false }

func (*jsonInitPlatform) SourceRepoURL(owner, repo string) string {
	return "https://github.com/" + owner + "/" + repo
}
