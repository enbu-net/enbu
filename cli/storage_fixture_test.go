package cli

import (
	"context"
	"strings"
	"sync"
	"testing"

	"github.com/enbu-net/enbu/app"
	"github.com/enbu-net/enbu/pkg/config"
	"github.com/enbu-net/enbu/pkg/storage"
	"github.com/enbu-net/enbu/pkg/storage/storagetest"
)

const testWorkspaceID = "11111111-1111-4111-8111-111111111111"

func prepareCLIApp(t *testing.T, a *app.App) {
	t.Helper()
	if a.RepositoryDir == "" {
		a.RepositoryDir = t.TempDir()
	}
	cfg, err := config.LoadProjectFrom(a.RepositoryDir)
	if err != nil {
		cfg = config.NewProjectWithEnvironment("default")
	}
	cfg.WorkspaceID = testWorkspaceID
	cfg.Storage.URL = "local:///unused"
	if err := config.SaveProjectTo(a.RepositoryDir, cfg); err != nil {
		t.Fatal(err)
	}
}

// putRecord is one write to a ref, with the version the app last read for it.
type putRecord struct {
	key      string
	expected storage.Version
	lastRead storage.Version
}

// refRecorder observes ref traffic of a real in-memory store, so tests can
// assert how many writes a command made and which version each was based on.
type refRecorder struct {
	storagetest.Objects
	mu      sync.Mutex
	puts    []putRecord
	lastGet map[string]storage.Version
	failGet map[string]error // by key prefix
}

func (r *refRecorder) Get(ctx context.Context, key string) ([]byte, storage.Version, error) {
	r.mu.Lock()
	for prefix, err := range r.failGet {
		if strings.HasPrefix(key, prefix) {
			r.mu.Unlock()
			return nil, "", err
		}
	}
	r.mu.Unlock()
	data, v, err := r.Objects.Get(ctx, key)
	if err == nil {
		r.mu.Lock()
		r.lastGet[key] = v
		r.mu.Unlock()
	}
	return data, v, err
}

func (r *refRecorder) Put(ctx context.Context, key string, o []byte, v storage.Version) error {
	r.mu.Lock()
	r.puts = append(r.puts, putRecord{key: key, expected: v, lastRead: r.lastGet[key]})
	r.mu.Unlock()
	return r.Objects.Put(ctx, key, o, v)
}

func (r *refRecorder) reset() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.puts = nil
}

// secretPuts returns the writes to secret and history refs since the last reset.
func (r *refRecorder) secretPuts() []putRecord {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []putRecord
	for _, p := range r.puts {
		if strings.HasPrefix(p.key, "secrets-") || strings.HasPrefix(p.key, "hist-") {
			out = append(out, p)
		}
	}
	return out
}

// bootstrapCLIApp points a at store and creates the workspace the way the first
// device does: workspace ref, signing key and genesis Control. Writes made
// during setup are not recorded.
func bootstrapCLIApp(t *testing.T, a *app.App, store *storage.Store) *refRecorder {
	t.Helper()
	rec := &refRecorder{Objects: storagetest.ToObjects(store), lastGet: map[string]storage.Version{}, failGet: map[string]error{}}
	a.Storage = storagetest.Wrap(store, rec)
	a.CheckpointDir = t.TempDir()
	prepareCLIApp(t, a)
	if err := rec.Objects.Put(context.Background(), "enbu-workspace", []byte(testWorkspaceID), ""); err != nil {
		t.Fatal(err)
	}
	if _, err := a.InitializeRepository(context.Background()); err != nil {
		t.Fatalf("initialize workspace: %v", err)
	}
	rec.reset()
	return rec
}

// newSeededApp returns a bootstrapped app whose default environment already
// holds secrets (none if nil), plus the recorder of its ref traffic.
func newSeededApp(t *testing.T, secrets map[string]string) (*app.App, *refRecorder) {
	t.Helper()
	a := &app.App{
		TokenProvider: &deleteTestTokenProvider{},
		RepoDetector:  &deleteTestRepoDetector{},
		Identities:    &staticKeyStore{},
	}
	rec := bootstrapCLIApp(t, a, storagetest.NewMemory())
	for k, v := range secrets {
		if err := a.AddSecret(context.Background(), "default", k, v); err != nil {
			t.Fatal(err)
		}
	}
	rec.reset()
	return a, rec
}
