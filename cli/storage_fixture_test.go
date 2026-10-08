package cli

import (
	"context"
	"sync"
	"testing"

	"github.com/enbu-net/enbu/app"
	"github.com/enbu-net/enbu/pkg/config"
	"github.com/enbu-net/enbu/pkg/storage"
	"github.com/enbu-net/enbu/pkg/storage/storagetest"
	"github.com/fxamacker/cbor/v2"
	"github.com/opencontainers/go-digest"
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

// putRecord is one published revision of a secret state.
type putRecord struct {
	rev     digest.Digest
	parents []digest.Digest
}

// stateRecorder observes the State revisions an app publishes to a real
// in-memory store, so tests can assert how many writes a command made and which
// revisions each was based on.
type stateRecorder struct {
	mu         sync.Mutex
	puts       []putRecord
	failStates error // makes every read of secret states fail with it
}

func (r *stateRecorder) hooks() storagetest.Hooks {
	return storagetest.Hooks{
		Publish: func(ctx context.Context, next storage.Store, o storage.Object) error {
			if err := next.Publish(ctx, o); err != nil {
				return err
			}
			if o.Kind == storage.KindState {
				r.mu.Lock()
				r.puts = append(r.puts, putRecord{rev: o.Rev, parents: parentsOf(o.Signed)})
				r.mu.Unlock()
			}
			return nil
		},
		Discover: func(ctx context.Context, next storage.Store, kind storage.Kind, scope string) ([]digest.Digest, error) {
			if err := r.stateFailure(kind); err != nil {
				return nil, err
			}
			return next.Discover(ctx, kind, scope)
		},
		Fetch: func(ctx context.Context, next storage.Store, kind storage.Kind, scope string, rev digest.Digest) (storage.Object, error) {
			if err := r.stateFailure(kind); err != nil {
				return storage.Object{}, err
			}
			return next.Fetch(ctx, kind, scope, rev)
		},
	}
}

func (r *stateRecorder) stateFailure(kind storage.Kind) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if kind == storage.KindState {
		return r.failStates
	}
	return nil
}

// parentsOf reads the parents a signed State names, without verifying it.
func parentsOf(signed []byte) []digest.Digest {
	var outer struct {
		Body []byte `cbor:"body"`
	}
	var body struct {
		Parents []digest.Digest `cbor:"parents"`
	}
	if cbor.Unmarshal(signed, &outer) != nil || cbor.Unmarshal(outer.Body, &body) != nil {
		return nil
	}
	return body.Parents
}

func (r *stateRecorder) reset() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.puts = nil
}

// secretPuts returns the State revisions published since the last reset.
func (r *stateRecorder) secretPuts() []putRecord {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]putRecord(nil), r.puts...)
}

// bootstrapCLIApp points a at store and creates the workspace the way the first
// device does: signing key and genesis Control. Writes made
// during setup are not recorded.
func bootstrapCLIApp(t *testing.T, a *app.App, store storage.Store) *stateRecorder {
	t.Helper()
	rec := &stateRecorder{}
	a.Storage = storagetest.Wrap(store, rec.hooks())
	a.CheckpointDir = t.TempDir()
	prepareCLIApp(t, a)
	if _, err := a.InitializeRepository(context.Background()); err != nil {
		t.Fatalf("initialize workspace: %v", err)
	}
	rec.reset()
	return rec
}

// newSeededApp returns a bootstrapped app whose default environment already
// holds secrets (none if nil), plus the recorder of its State publishes.
func newSeededApp(t *testing.T, secrets map[string]string) (*app.App, *stateRecorder) {
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
