package app

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/enbu-net/enbu/pkg/age"
	"github.com/enbu-net/enbu/pkg/apperr"
	"github.com/enbu-net/enbu/pkg/bundle"
	"github.com/enbu-net/enbu/pkg/oci"
)

// Only the current artifact is intercepted; recipient and snapshot operations
// continue to use real encryption and the in-memory registry.
type hookedRegistry struct {
	Registry
	push   func(context.Context, string, string, []byte, string, *oci.PushOptions) error
	digest func(context.Context, string, string) (string, error)
	pull   func(context.Context, string, string) ([]byte, error)
	tags   func(context.Context, string, string) ([]string, error)
}

func (r *hookedRegistry) Push(ctx context.Context, ref, mediaType string, data []byte, token string, opts *oci.PushOptions) error {
	if r.push != nil {
		return r.push(ctx, ref, mediaType, data, token, opts)
	}
	return r.Registry.Push(ctx, ref, mediaType, data, token, opts)
}

func (r *hookedRegistry) GetDigest(ctx context.Context, ref, token string) (string, error) {
	if r.digest != nil {
		return r.digest(ctx, ref, token)
	}
	return r.Registry.GetDigest(ctx, ref, token)
}

func (r *hookedRegistry) Pull(ctx context.Context, ref, token string) ([]byte, error) {
	if r.pull != nil {
		return r.pull(ctx, ref, token)
	}
	return r.Registry.Pull(ctx, ref, token)
}

func (r *hookedRegistry) ListTags(ctx context.Context, ref, token string) ([]string, error) {
	if r.tags != nil {
		return r.tags(ctx, ref, token)
	}
	return r.Registry.ListTags(ctx, ref, token)
}

type retryEvents struct {
	recordingEvents
	retries [][2]int
}

func (e *retryEvents) OnConflictRetry(attempt, limit int) {
	e.retries = append(e.retries, [2]int{attempt, limit})
}

func TestSecretWritesHandleConflicts(t *testing.T) {
	for _, operation := range []struct {
		name string
		run  func(*App) error
		want map[string]string
	}{
		{"add", func(a *App) error { return a.AddSecret(context.Background(), "default", "NEW", "added") }, map[string]string{"KEY": "original", "NEW": "added", "CONCURRENT": "keep"}},
		{"edit", func(a *App) error { return a.EditSecret(context.Background(), "default", "KEY", "edited") }, map[string]string{"KEY": "edited", "CONCURRENT": "keep"}},
		{"delete", func(a *App) error { return a.DeleteSecret(context.Background(), "default", "KEY") }, map[string]string{"CONCURRENT": "keep"}},
		{"restore", func(a *App) error { return a.RestoreHistory(context.Background(), "default", 1) }, map[string]string{"KEY": "original"}},
	} {
		t.Run(operation.name, func(t *testing.T) {
			for _, failure := range []string{"retry succeeds", "exhausted", "non conflict", "snapshot failure"} {
				t.Run(failure, func(t *testing.T) {
					kp := mustKeyPair(t)
					a := newTestApp(t, "owner", "repo", "default", kp, map[string]string{"KEY": "original"})
					a.RepositoryDir = t.TempDir()
					base := a.Registry
					ref := a.secretsRef("owner", "repo", "default")
					initial := map[string]string{"KEY": "original"}
					if operation.name == "restore" {
						initial = map[string]string{"KEY": "updated"}
						data, err := age.EncryptForPublicKeys(bundle.Marshal(initial), []string{kp.PublicKey})
						if err != nil {
							t.Fatal(err)
						}
						if err := base.Push(context.Background(), ref, "application/vnd.enbu.secrets.age.v1", data, "tok", nil); err != nil {
							t.Fatal(err)
						}
					}
					events := &retryEvents{}
					a.Events = events
					cause := apperr.New(apperr.CodeConflict, "concurrent update", nil)
					if failure == "non conflict" || failure == "snapshot failure" {
						cause = apperr.New(apperr.CodeAccessDenied, "push denied", nil)
					}
					writes, snapshots := 0, 0
					a.Registry = &hookedRegistry{Registry: base, push: func(ctx context.Context, target, media string, data []byte, token string, opts *oci.PushOptions) error {
						if target != ref {
							snapshots++
							if opts.ExpectedDigest != "" {
								t.Fatal("snapshot must not use the current artifact's digest")
							}
							if failure == "snapshot failure" {
								return cause
							}
							return base.Push(ctx, target, media, data, token, opts)
						}
						writes++
						current, err := base.GetDigest(ctx, ref, token)
						if err != nil {
							t.Fatal(err)
						}
						if opts.ExpectedDigest != current {
							t.Fatalf("expected digest = %q, current = %q", opts.ExpectedDigest, current)
						}
						if failure == "exhausted" || failure == "non conflict" {
							return cause
						}
						if failure == "retry succeeds" && writes == 1 {
							// Another user changes the artifact before the retry. The next
							// attempt must re-read its contents and its new digest.
							concurrent, err := age.EncryptForPublicKeys(bundle.Marshal(map[string]string{"KEY": "original", "CONCURRENT": "keep"}), []string{kp.PublicKey})
							if err != nil {
								t.Fatal(err)
							}
							if err := base.Push(ctx, ref, media, concurrent, token, nil); err != nil {
								t.Fatal(err)
							}
							return cause
						}
						return base.Push(ctx, target, media, data, token, opts)
					}}
					err := operation.run(a)
					wantWrites, wantSnapshots := 1, 1
					var wantRetries [][2]int
					switch failure {
					case "retry succeeds":
						wantWrites = 2
						wantRetries = [][2]int{{1, maxRetries}}
					case "exhausted":
						wantWrites = maxRetries
						wantSnapshots = 0
						wantRetries = [][2]int{{1, maxRetries}, {2, maxRetries}}
					case "non conflict":
						wantSnapshots = 0
					}
					if writes != wantWrites || snapshots != wantSnapshots || !reflect.DeepEqual(events.retries, wantRetries) {
						t.Fatalf("writes=%d snapshots=%d retries=%v, want %d/%d/%v", writes, snapshots, events.retries, wantWrites, wantSnapshots, wantRetries)
					}
					if failure == "exhausted" || failure == "non conflict" {
						if !errors.Is(err, cause) || !apperr.Is(err, cause.Code()) {
							t.Fatalf("error = %v, want preserved cause and code", err)
						}
						got, readErr := a.ListSecrets(context.Background(), "default")
						if readErr != nil || !reflect.DeepEqual(got, initial) {
							t.Fatalf("failed write changed secrets: %v, %v", got, readErr)
						}
						return
					}
					if err != nil {
						t.Fatal(err)
					}
					want := operation.want
					if failure == "snapshot failure" {
						want = make(map[string]string)
						for k, v := range operation.want {
							if k != "CONCURRENT" {
								want[k] = v
							}
						}
					}
					got, err := a.ListSecrets(context.Background(), "default")
					if err != nil || !reflect.DeepEqual(got, want) {
						t.Fatalf("secrets = %v, %v, want %v", got, err, want)
					}
				})
			}
		})
	}
}

func TestSyncSecretsCancellationDuringConflict(t *testing.T) {
	a := newTestApp(t, "owner", "repo", "default", mustKeyPair(t), map[string]string{"KEY": "value"})
	a.RepositoryDir = t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	base := a.Registry
	pushes := 0
	a.Registry = &hookedRegistry{Registry: base, push: func(context.Context, string, string, []byte, string, *oci.PushOptions) error {
		pushes++
		cancel()
		return apperr.New(apperr.CodeConflict, "digest changed", nil)
	}}
	if err := a.SyncSecrets(ctx, "default"); !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want cancellation", err)
	}
	if pushes != 1 {
		t.Fatalf("pushes = %d, want 1", pushes)
	}
}

func TestSyncSecretsDetectsChangeBeforePush(t *testing.T) {
	a := newTestApp(t, "owner", "repo", "default", mustKeyPair(t), map[string]string{"KEY": "value"})
	base := a.Registry
	reads, pushes := 0, 0
	a.Registry = &hookedRegistry{Registry: base,
		digest: func(ctx context.Context, ref, token string) (string, error) {
			reads++
			if reads == 2 {
				return "sha256:changed", nil
			}
			return base.GetDigest(ctx, ref, token)
		},
		push: func(context.Context, string, string, []byte, string, *oci.PushOptions) error { pushes++; return nil },
	}
	ids, err := LoadIdentitiesForRepo(a.Identities, "owner", "repo")
	if err != nil {
		t.Fatal(err)
	}
	defer CloseIdentities(ids)
	err = a.doSync(context.Background(), a.secretsRef("owner", "repo", "default"), a.registryRef("owner", "repo"), "tok", ids, &oci.PushOptions{})
	if !apperr.Is(err, apperr.CodeConflict) || pushes != 0 {
		t.Fatalf("error=%v pushes=%d, want conflict before any push", err, pushes)
	}
}
