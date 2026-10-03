package app

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/enbu-net/enbu/pkg/age"
	"github.com/enbu-net/enbu/pkg/apperr"
	"github.com/enbu-net/enbu/pkg/bundle"
	"github.com/enbu-net/enbu/pkg/config"
	"github.com/enbu-net/enbu/pkg/storage"
)

func TestSecretOperationsPropagateFailuresWithoutWriting(t *testing.T) {
	ctx := context.Background()
	for _, operation := range []struct {
		name string
		run  func(*App) error
	}{
		{"list", func(a *App) error { _, err := a.ListSecrets(ctx, "default"); return err }},
		{"pull", func(a *App) error { _, _, _, err := a.PullSecrets(ctx, "default"); return err }},
		{"add", func(a *App) error { return a.AddSecret(ctx, "default", "NEW", "value") }},
		{"edit", func(a *App) error { return a.EditSecret(ctx, "default", "KEY", "value") }},
		{"delete", func(a *App) error { return a.DeleteSecret(ctx, "default", "KEY") }},
		{"sync", func(a *App) error { return a.SyncSecrets(ctx, "default") }},
		{"restore", func(a *App) error { return a.RestoreHistory(ctx, "default", 1) }},
		{"diff", func(a *App) error { _, err := a.DiffHistory(ctx, "default", 1, 1); return err }},
	} {
		t.Run(operation.name, func(t *testing.T) {
			for _, failure := range []string{"config", "workspace", "identity", "storage", "ciphertext", "bundle"} {
				t.Run(failure, func(t *testing.T) {
					kp := mustKeyPair(t)
					// One existing secret also gives history operations a snapshot.
					a := newTestApp(t, "owner", "repo", "default", kp, map[string]string{"KEY": "original"})
					cause := errors.New("dependency unavailable")
					wantCode := apperr.CodeInternal
					preserveCause := false
					base := a.Storage
					hook := &hookedStorage{Storage: base}
					writes := 0
					hook.put = func(context.Context, string, storage.Object, storage.Version) error { writes++; return nil }
					a.Storage = hook
					switch failure {
					case "config":
						if err := os.WriteFile(filepath.Join(a.RepositoryDir, "enbu.toml"), []byte("version = ["), 0o600); err != nil {
							t.Fatal(err)
						}
					case "workspace":
						hook.get = func(ctx context.Context, key string) (storage.Object, storage.Version, error) {
							if key == workspaceKey {
								return storage.Object{MediaType: workspaceMediaType, Data: []byte("other-workspace")}, "", nil
							}
							return base.Get(ctx, key)
						}
						wantCode = apperr.CodeInvalidArgument
					case "identity":
						a.Identities = newMemKeyStore()
						wantCode = apperr.CodeNotInitialized
					case "storage":
						hook.get = func(context.Context, string) (storage.Object, storage.Version, error) {
							return storage.Object{}, "", cause
						}
						preserveCause = true
					case "ciphertext", "bundle":
						data := []byte("invalid age ciphertext")
						if failure == "bundle" {
							var err error
							data, err = age.EncryptForPublicKeys([]byte("invalid JSON"), []string{kp.PublicKey})
							if err != nil {
								t.Fatal(err)
							}
						}
						hook.get = func(ctx context.Context, key string) (storage.Object, storage.Version, error) {
							if key == secretsTag("default") || strings.HasPrefix(key, snapshotPrefix("default")) {
								return storage.Object{MediaType: secretsMediaType, Data: data}, "corrupt", nil
							}
							return base.Get(ctx, key)
						}
					}
					err := operation.run(a)
					if !apperr.Is(err, wantCode) {
						t.Fatalf("error = %v, want %s", err, wantCode)
					}
					if preserveCause && !errors.Is(err, cause) {
						t.Fatalf("error = %v, lost cause", err)
					}
					if writes != 0 {
						t.Fatalf("writes = %d after failed dependency", writes)
					}
				})
			}
		})
	}
}

func TestSecretWritesRejectInvalidRecipients(t *testing.T) {
	for _, operation := range []struct {
		name string
		run  func(*App) error
	}{
		{"add", func(a *App) error { return a.AddSecret(context.Background(), "default", "NEW", "value") }},
		{"edit", func(a *App) error { return a.EditSecret(context.Background(), "default", "KEY", "value") }},
		{"delete", func(a *App) error { return a.DeleteSecret(context.Background(), "default", "KEY") }},
		{"sync", func(a *App) error { return a.SyncSecrets(context.Background(), "default") }},
		{"restore", func(a *App) error { return a.RestoreHistory(context.Background(), "default", 1) }},
	} {
		t.Run(operation.name, func(t *testing.T) {
			for _, recipients := range []string{"none", "malformed", "list failure"} {
				t.Run(recipients, func(t *testing.T) {
					a := newTestApp(t, "owner", "repo", "default", mustKeyPair(t), map[string]string{"KEY": "original"})
					base := a.Storage
					writes := 0
					cause := errors.New("list unavailable")
					listCalls := 0
					malformedKey := RecipientKey("invalid recipient")
					a.Storage = &hookedStorage{Storage: base,
						list: func(ctx context.Context, prefix string) ([]string, error) {
							listCalls++
							// History listing succeeds; only recipient listing is intercepted.
							if prefix != RecipientTagPrefix() {
								return base.List(ctx, prefix)
							}
							if recipients == "list failure" {
								return nil, cause
							}
							if recipients == "malformed" {
								return []string{malformedKey}, nil
							}
							return nil, nil
						},
						get: func(ctx context.Context, key string) (storage.Object, storage.Version, error) {
							if key == malformedKey {
								return storage.Object{MediaType: recipientMediaType, Data: []byte("invalid recipient")}, "", nil
							}
							return base.Get(ctx, key)
						},
						put: func(context.Context, string, storage.Object, storage.Version) error { writes++; return nil },
					}
					err := operation.run(a)
					wantListCalls := 1
					if operation.name == "restore" {
						wantListCalls = 2
					}
					if listCalls != wantListCalls {
						t.Fatalf("List calls = %d, want %d", listCalls, wantListCalls)
					}
					if !apperr.Is(err, apperr.CodeInternal) || writes != 0 {
						t.Fatalf("error=%v writes=%d, want failure without writes", err, writes)
					}
					if recipients == "list failure" && !errors.Is(err, cause) {
						t.Fatalf("error = %v, lost cause", err)
					}
				})
			}
		})
	}
}

func TestPullSecretsToFilePreservesExistingFileOnFailure(t *testing.T) {
	for _, failure := range []string{"decryption", "invalid dotenv key", "missing output directory"} {
		t.Run(failure, func(t *testing.T) {
			secrets := map[string]string{"KEY": "new"}
			if failure == "invalid dotenv key" {
				secrets = map[string]string{"BAD\nKEY": "value"}
			}
			a := newTestApp(t, "owner", "repo", "default", mustKeyPair(t), secrets)
			output := filepath.Join(a.RepositoryDir, ".env")
			if err := os.WriteFile(output, []byte("original"), 0o600); err != nil {
				t.Fatal(err)
			}
			if failure == "decryption" {
				store := newMemKeyStore()
				other := mustKeyPair(t)
				if err := store.storeSecret(KeystoreService, testWorkspaceID, []byte(other.Identity.String())); err != nil {
					t.Fatal(err)
				}
				a.Identities = store
			}
			if failure == "missing output directory" {
				setSecretTestOutput(t, a, "missing/.env")
			}
			if err := a.PullSecretsToFile(context.Background(), "default"); err == nil {
				t.Fatal("expected failure")
			}
			got, err := os.ReadFile(output)
			if err != nil || string(got) != "original" {
				t.Fatalf("existing file = %q, %v", got, err)
			}
		})
	}
}

func TestPullSecretsDataUsesRepositoryOutput(t *testing.T) {
	a := newTestApp(t, "owner", "repo", "default", mustKeyPair(t), map[string]string{"KEY": "value"})
	setSecretTestOutput(t, a, "custom.env")
	result, err := a.PullSecretsData(context.Background(), "default")
	if err != nil {
		t.Fatal(err)
	}
	if result.Environment != "default" || result.Output != "custom.env" || !reflect.DeepEqual(result.Secrets, map[string]string{"KEY": "value"}) {
		t.Fatalf("result = %#v", result)
	}
	if err := a.PullSecretsToFile(context.Background(), "default"); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(a.RepositoryDir, "custom.env"))
	want, marshalErr := bundle.ToDotEnv(result.Secrets)
	if err != nil || marshalErr != nil || string(got) != string(want) {
		t.Fatalf("file = %q, %v, want %q", got, err, want)
	}
}

func setSecretTestOutput(t *testing.T, a *App, output string) {
	t.Helper()
	cfg, err := config.LoadProjectFrom(a.RepositoryDir)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Environments["default"] = config.EnvironmentConfig{Output: output}
	if err := config.SaveProjectTo(a.RepositoryDir, cfg); err != nil {
		t.Fatal(err)
	}
}
