package cli

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/enbu-net/enbu/app"
	"github.com/enbu-net/enbu/pkg/age"
	"github.com/enbu-net/enbu/pkg/bundle"
	"github.com/enbu-net/enbu/pkg/provider"
	gitprovider "github.com/enbu-net/enbu/pkg/provider/git"
	"github.com/enbu-net/enbu/pkg/storage"
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
			keyPair, registry := newAddEditRegistry(t, tt.initial)
			commandArgs := append([]string{tt.command, "--json"}, tt.args...)
			envelope := executeJSON(t, NewWithApp("test", newAddEditApp(t, keyPair, registry)), commandArgs...)
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
	keyPair, registry := newAddEditRegistry(t, map[string]string{
		"API_KEY":   "secret",
		"MULTILINE": "first\nsecond",
	})
	a := newAddEditApp(t, keyPair, registry)
	a.RepositoryDir = dir
	prepareCLIApp(t, a)

	envelope := executeJSON(t, NewWithApp("test", a), "pull", "--json")
	data := objectField(t, envelope, "data")
	secrets := objectField(t, data, "secrets")
	if got := stringField(t, secrets, "MULTILINE"); got != "first\nsecond" {
		t.Fatalf("multiline secret = %q", got)
	}
	if _, err := os.Stat(filepath.Join(dir, ".env")); !os.IsNotExist(err) {
		t.Fatalf("pull --json wrote .env: %v", err)
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
	keyPair, err := age.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	registry := newEnvRegistry()
	a := &app.App{
		Storage:       registry,
		TokenProvider: &deleteTestTokenProvider{},
		RepoDetector:  &deleteTestRepoDetector{},
		Identities:    &staticKeyStore{key: []byte(keyPair.Identity.String())},
	}
	prepareCLIApp(t, a)
	registryRef := ""
	pushEncryptedHistory(t, registry, keyPair, registryRef+"hist-37a8eec1ce19687d132fe29051dca629d164e2c4958ba141d5f4133a33f0688f-1000-11111111-1111-4111-8111-111111111111", map[string]string{"A": "1"})
	pushEncryptedHistory(t, registry, keyPair, registryRef+"hist-37a8eec1ce19687d132fe29051dca629d164e2c4958ba141d5f4133a33f0688f-2000-11111111-1111-4111-8111-111111111111", map[string]string{"A": "2", "B": "3"})
	recipientTag := app.RecipientKey(keyPair.PublicKey)
	if err := registry.Put(context.Background(), recipientTag, storage.Object{MediaType: "application/vnd.enbu.recipient.age.v1", Data: []byte(keyPair.PublicKey)}, ""); err != nil {
		t.Fatal(err)
	}

	list := executeJSON(t, NewWithApp("test", a), "history", "list", "--json")
	entries, ok := objectField(t, list, "data")["entries"].([]any)
	if !ok || len(entries) != 2 {
		t.Fatalf("entries = %#v", objectField(t, list, "data")["entries"])
	}

	diff := executeJSON(t, NewWithApp("test", a), "history", "diff", "1", "2", "--json")
	diffData := objectField(t, diff, "data")
	added, ok := diffData["added"].([]any)
	if !ok || len(added) != 1 || added[0] != "B" {
		t.Fatalf("added = %#v", diffData["added"])
	}

	restore := executeJSON(t, NewWithApp("test", a), "history", "restore", "1", "--json")
	if got := objectField(t, restore, "data")["version"]; got != float64(1) {
		t.Fatalf("version = %#v", got)
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

	registry := newEnvRegistry()
	a := &app.App{
		Storage:       registry,
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

	publicKey := stringField(t, data, "public_key")
	if publicKey == "" {
		t.Fatal("public_key is empty")
	}
	recipientTag := app.RecipientKey(publicKey)
	if _, ok := registry.data[recipientTag]; !ok {
		t.Fatalf("recipient tag %q was not registered", recipientTag)
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
	if err := os.WriteFile(filepath.Join(dir, "enbu.toml"), []byte(`version = "v1alpha2"
default_env = "default"

[env.default]
output = ".env"
`), 0o644); err != nil {
		t.Fatal(err)
	}

	registry := newEnvRegistry()
	other, err := age.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, err := age.EncryptForPublicKeys([]byte(`{"KEY":"value"}`), []string{other.PublicKey})
	if err != nil {
		t.Fatal(err)
	}
	if err := registry.Put(context.Background(), "secrets-default", storage.Object{MediaType: "application/vnd.enbu.secrets.age.v1", Data: ciphertext}, ""); err != nil {
		t.Fatal(err)
	}
	a := &app.App{
		Storage:       registry,
		TokenProvider: &deleteTestTokenProvider{},
		RepoDetector:  &deleteTestRepoDetector{},
		Identities:    &staticKeyStore{},
		Git:           &jsonInitGit{root: dir},
		Platform:      &jsonInitPlatform{},
	}
	a.RepositoryDir = dir
	prepareCLIApp(t, a)
	envelope := executeJSON(t, NewWithApp("test", a), "init", "--json")
	data := objectField(t, envelope, "data")
	if got := stringField(t, data, "mode"); got != "join" {
		t.Fatalf("mode = %q", got)
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

func pushEncryptedHistory(
	t *testing.T,
	registry *envRegistry,
	keyPair *age.KeyPair,
	ref string,
	secrets map[string]string,
) {
	t.Helper()
	ciphertext, err := age.EncryptForPublicKeys(bundle.Marshal(secrets), []string{keyPair.PublicKey})
	if err != nil {
		t.Fatal(err)
	}
	if err := registry.Put(context.Background(), ref, storage.Object{MediaType: "application/vnd.enbu.secrets.age.v1", Data: ciphertext}, ""); err != nil {
		t.Fatalf("push %s: %v", fmt.Sprint(ref), err)
	}
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
