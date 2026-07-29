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
	"github.com/enbu-net/enbu/pkg/oci"
	"github.com/enbu-net/enbu/pkg/provider"
	gitprovider "github.com/enbu-net/enbu/pkg/provider/git"
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
			envelope := executeJSON(t, NewWithApp("test", newAddEditApp(keyPair, registry)), commandArgs...)
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
	a := newAddEditApp(keyPair, registry)
	a.RepositoryDir = dir

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
		Registry:      registry,
		TokenProvider: &deleteTestTokenProvider{},
		RepoDetector:  &deleteTestRepoDetector{},
		KeyStore:      &staticKeyStore{key: []byte(keyPair.Identity.String())},
	}
	registryRef := "ghcr.io/owner/repo-enbu"
	pushEncryptedHistory(t, registry, keyPair, registryRef+":secrets-default-1000", map[string]string{"A": "1"})
	pushEncryptedHistory(t, registry, keyPair, registryRef+":secrets-default-2000", map[string]string{"A": "2", "B": "3"})
	recipientTag := app.RecipientTagPrefix() + oci.CleanTag(fmt.Sprintf("alice-%s", age.Fingerprint(keyPair.PublicKey)))
	if err := registry.Push(context.Background(), registryRef+":"+recipientTag, "", []byte(keyPair.PublicKey), "", nil); err != nil {
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
		Registry:      registry,
		TokenProvider: &deleteTestTokenProvider{},
		RepoDetector:  &deleteTestRepoDetector{},
		KeyStore:      &staticKeyStore{},
		Git:           &jsonInitGit{root: dir},
		Platform:      &jsonInitPlatform{},
	}
	envelope := executeJSON(t, NewWithApp("test", a), "init", "--json")
	data := objectField(t, envelope, "data")
	if got := stringField(t, data, "mode"); got != "initialize" {
		t.Fatalf("mode = %q", got)
	}
	if registered, _ := data["recipient_registered"].(bool); !registered {
		t.Fatalf("recipient_registered = %#v", data["recipient_registered"])
	}
	publicKey := stringField(t, data, "public_key")
	if publicKey == "" {
		t.Fatal("public_key is empty")
	}
	recipientTag := app.RecipientTagPrefix() + oci.CleanTag(fmt.Sprintf("alice-%s", age.Fingerprint(publicKey)))
	if _, ok := registry.data["ghcr.io/owner/repo-enbu:"+recipientTag]; !ok {
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
	if err := os.WriteFile(filepath.Join(dir, "enbu.toml"), []byte(`version = "v1alpha1"
default_env = "default"

[env.default]
output = ".env"
`), 0o644); err != nil {
		t.Fatal(err)
	}

	registry := newEnvRegistry()
	if err := registry.Push(context.Background(), "ghcr.io/owner/repo-enbu:secrets-default", "", []byte("ciphertext"), "", nil); err != nil {
		t.Fatal(err)
	}
	a := &app.App{
		Registry:      registry,
		TokenProvider: &deleteTestTokenProvider{},
		RepoDetector:  &deleteTestRepoDetector{},
		KeyStore:      &staticKeyStore{},
		Git:           &jsonInitGit{root: dir},
		Platform:      &jsonInitPlatform{},
	}
	envelope := executeJSON(t, NewWithApp("test", a), "init", "--json")
	data := objectField(t, envelope, "data")
	if got := stringField(t, data, "mode"); got != "join" {
		t.Fatalf("mode = %q", got)
	}
	if updated, _ := data["gitignore_updated"].(bool); !updated {
		t.Fatalf("gitignore_updated = %#v", data["gitignore_updated"])
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
	content := `version = "v1alpha1"
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
	if err := registry.Push(context.Background(), ref, "", ciphertext, "", nil); err != nil {
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
