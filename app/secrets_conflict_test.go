package app

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/enbu-net/enbu/pkg/age"
	"github.com/enbu-net/enbu/pkg/apperr"
	"github.com/enbu-net/enbu/pkg/bundle"
	"github.com/enbu-net/enbu/pkg/storage"
	"github.com/enbu-net/enbu/pkg/storage/storagetest"
)

// Hooks preserve real encryption and the in-memory Storage contract.
type hookedStorage struct {
	storagetest.Objects
	put  func(context.Context, string, []byte, storage.Version) error
	get  func(context.Context, string) ([]byte, storage.Version, error)
	list func(context.Context, string) ([]string, error)
}

func (s *hookedStorage) Put(ctx context.Context, key string, o []byte, v storage.Version) error {
	if s.put != nil {
		return s.put(ctx, key, o, v)
	}
	return s.Objects.Put(ctx, key, o, v)
}
func (s *hookedStorage) Get(ctx context.Context, key string) ([]byte, storage.Version, error) {
	if s.get != nil {
		return s.get(ctx, key)
	}
	return s.Objects.Get(ctx, key)
}
func (s *hookedStorage) List(ctx context.Context, prefix string) ([]string, error) {
	if s.list != nil {
		return s.list(ctx, prefix)
	}
	return s.Objects.List(ctx, prefix)
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
					base := a.Storage
					ref := secretsTag("default")
					initial := map[string]string{"KEY": "original"}
					if operation.name == "restore" {
						initial = map[string]string{"KEY": "updated"}
						data, err := age.EncryptForPublicKeys(bundle.Marshal(initial), []string{kp.PublicKey})
						if err != nil {
							t.Fatal(err)
						}
						_, version, err := getRef(context.Background(), base, ref)
						if err != nil {
							t.Fatal(err)
						}
						if err := putRef(context.Background(), base, ref, data, version); err != nil {
							t.Fatal(err)
						}
					}
					events := &retryEvents{}
					a.Events = events
					var cause = storage.ErrConflict
					wantCode := apperr.CodeConflict
					if failure == "non conflict" || failure == "snapshot failure" {
						cause = apperr.New(apperr.CodeAccessDenied, "push denied", nil)
						wantCode = apperr.CodeAccessDenied
					}
					writes, snapshots := 0, 0
					a.Storage = storagetest.FromObjects(&hookedStorage{Objects: storagetest.ToObjects(base), put: func(ctx context.Context, target string, o []byte, version storage.Version) error {
						if target != ref {
							snapshots++
							if version != "" {
								t.Fatal("snapshot must not use the current artifact's digest")
							}
							if failure == "snapshot failure" {
								return cause
							}
							return putRef(ctx, base, target, o, version)
						}
						writes++
						_, current, err := getRef(ctx, base, ref)
						if err != nil {
							t.Fatal(err)
						}
						if version != current {
							t.Fatalf("expected digest = %q, current = %q", version, current)
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
							if err := putRef(ctx, base, ref, concurrent, current); err != nil {
								t.Fatal(err)
							}
							return cause
						}
						return putRef(ctx, base, target, o, version)
					}})
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
						if !errors.Is(err, cause) || !apperr.Is(err, wantCode) {
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
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	base := a.Storage
	pushes := 0
	a.Storage = storagetest.FromObjects(&hookedStorage{Objects: storagetest.ToObjects(base), put: func(context.Context, string, []byte, storage.Version) error {
		pushes++
		cancel()
		return storage.ErrConflict
	}})
	if err := a.SyncSecrets(ctx, "default"); !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want cancellation", err)
	}
	if pushes != 1 {
		t.Fatalf("pushes = %d, want 1", pushes)
	}
}

func TestSyncSecretsPassesReadVersion(t *testing.T) {
	a := newTestApp(t, "owner", "repo", "default", mustKeyPair(t), map[string]string{"KEY": "value"})
	base := a.Storage
	reads, writes := 0, 0
	const version storage.Version = "opaque-version"
	a.Storage = storagetest.FromObjects(&hookedStorage{Objects: storagetest.ToObjects(base),
		get: func(ctx context.Context, key string) ([]byte, storage.Version, error) {
			o, v, err := getRef(ctx, base, key)
			if key == secretsTag("default") {
				reads++
				v = version
			}
			return o, v, err
		},
		put: func(_ context.Context, key string, _ []byte, v storage.Version) error {
			writes++
			if key != secretsTag("default") || v != version {
				t.Fatalf("Put(%q) version=%q, want %q", key, v, version)
			}
			return nil
		},
	})
	if err := a.SyncSecrets(context.Background(), "default"); err != nil {
		t.Fatal(err)
	}
	if reads != 1 || writes != 1 {
		t.Fatalf("reads=%d writes=%d, want 1/1", reads, writes)
	}
}
