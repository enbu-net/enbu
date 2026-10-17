package app

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/enbu-net/enbu/pkg/age"
	"github.com/enbu-net/enbu/pkg/apperr"
	"github.com/enbu-net/enbu/pkg/bundle"
	"github.com/enbu-net/enbu/pkg/config"
	"github.com/enbu-net/enbu/pkg/storage"
	"github.com/enbu-net/enbu/pkg/storage/storagetest"
	"github.com/opencontainers/go-digest"
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
			for _, failure := range []string{"config", "identity", "storage", "ciphertext", "bundle"} {
				t.Run(failure, func(t *testing.T) {
					kp := mustKeyPair(t)
					// One existing secret also gives history operations a revision.
					a := newTestApp(t, "owner", "repo", "default", kp, map[string]string{"KEY": "original"})
					cause := errors.New("dependency unavailable")
					wantCode := apperr.CodeInternal
					preserveCause := false
					base := a.Storage
					writes := 0
					countWrites := func(ctx context.Context, next storage.Store, o storage.Object) error {
						writes++
						return next.Publish(ctx, o)
					}
					a.Storage = storagetest.Wrap(base, storagetest.Hooks{Publish: countWrites})
					switch failure {
					case "config":
						if err := os.WriteFile(filepath.Join(a.RepositoryDir, "enbu.toml"), []byte("version = ["), 0o600); err != nil {
							t.Fatal(err)
						}
					case "identity":
						a.Identities = newMemKeyStore()
						wantCode = apperr.CodeNotInitialized
					case "storage":
						a.Storage = storagetest.Wrap(base, storagetest.Hooks{
							Publish: countWrites,
							Fetch: func(ctx context.Context, next storage.Store, kind storage.Kind, scope string, rev digest.Digest) (storage.Object, error) {
								return storage.Object{}, cause
							},
							Discover: func(context.Context, storage.Store, storage.Kind, string) ([]digest.Digest, error) {
								return nil, cause
							},
						})
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
						// A legitimately signed revision whose ciphertext is bad becomes the
						// only head: signatures pass, so the failure is the decrypt or the
						// bundle parse itself.
						s, err := a.openSession(ctx)
						if err != nil {
							t.Fatal(err)
						}
						sv, err := s.loadResource(ctx, "default")
						if err != nil {
							t.Fatal(err)
						}
						publishRevision(t, base, a, s.workspace, s.resource("default"), s.head.Digest, data, sv.Heads[0].Digest)
						s.Close()
						writes = 0
					}
					err := operation.run(a)
					if !apperr.Is(err, wantCode) {
						t.Fatalf("error = %v, want %s", err, wantCode)
					}
					if preserveCause && !errors.Is(err, cause) {
						t.Fatalf("error = %v, want cause %v", err, cause)
					}
					if writes != 0 {
						t.Fatalf("%d writes after a failure", writes)
					}
				})
			}
		})
	}
}

func TestSecretWritesRejectUntrustedControl(t *testing.T) {
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
			a := newTestApp(t, "owner", "repo", "default", mustKeyPair(t), map[string]string{"KEY": "original"})
			base := a.Storage
			writes := 0
			cfg, err := a.loadProject()
			if err != nil {
				t.Fatal(err)
			}
			genesis := digest.Digest(cfg.ControlGenesis)
			// The genesis object is replaced by bytes that are not that control.
			a.Storage = storagetest.Wrap(base, storagetest.Hooks{
				Fetch: func(ctx context.Context, next storage.Store, kind storage.Kind, scope string, rev digest.Digest) (storage.Object, error) {
					if kind == storage.KindControl && rev == genesis {
						return storage.Object{Kind: kind, Rev: rev, Signed: []byte("not a control")}, nil
					}
					return next.Fetch(ctx, kind, scope, rev)
				},
				Publish: func(ctx context.Context, next storage.Store, o storage.Object) error {
					writes++
					return next.Publish(ctx, o)
				},
			})
			err = operation.run(a)
			if !apperr.Is(err, apperr.CodeUntrusted) || writes != 0 {
				t.Fatalf("error=%v writes=%d, want untrusted_state without writes", err, writes)
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
	env := cfg.Environments["default"]
	env.Output = output
	cfg.Environments["default"] = env
	if err := config.SaveProjectTo(a.RepositoryDir, cfg); err != nil {
		t.Fatal(err)
	}
}
