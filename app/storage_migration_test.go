package app

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"

	"github.com/enbu-net/enbu/app/apptest"
	"github.com/enbu-net/enbu/pkg/apperr"
	"github.com/enbu-net/enbu/pkg/config"
	"github.com/enbu-net/enbu/pkg/storage"
	"github.com/enbu-net/enbu/pkg/storage/storagetest"
	"github.com/opencontainers/go-digest"
)

func migrationApp(t *testing.T) *App {
	t.Helper()
	a := &App{Storage: newMemRegistry(), Identities: &apptest.Identities{}}
	prepareApp(t, a, "default")
	if _, err := a.InitializeRepository(context.Background(), InitOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := a.AddSecret(context.Background(), "default", "KEY", "first"); err != nil {
		t.Fatal(err)
	}
	if err := a.EditSecret(context.Background(), "default", "KEY", "second"); err != nil {
		t.Fatal(err)
	}
	return a
}

func TestMigrateStoragePreservesHistoryAndOldStorage(t *testing.T) {
	a := migrationApp(t)
	ctx := context.Background()
	old := a.Storage
	target := newMemRegistry()
	s, err := a.openSession(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	next := *s.cfg
	next.Storage.URL = "s3://new-bucket/team"
	if err := a.migrateStorage(ctx, s, target, &next); err != nil {
		t.Fatal(err)
	}
	cfg, err := a.loadProject()
	if err != nil || cfg.Storage.URL != next.Storage.URL {
		t.Fatalf("config %+v, %v", cfg, err)
	}
	for _, store := range []storage.Store{old, target} {
		a.Storage = store
		secrets, err := a.ListSecrets(ctx, "default")
		if err != nil || secrets["KEY"] != "second" {
			t.Fatalf("secrets %v, %v", secrets, err)
		}
		history, err := a.ListHistory(ctx, "default")
		if err != nil || len(history) != 2 {
			t.Fatalf("history %v, %v", history, err)
		}
	}
}

func TestMigrateStorageFailureLeavesConfigUnchangedAndCanRetry(t *testing.T) {
	a := migrationApp(t)
	ctx := context.Background()
	s, err := a.openSession(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	next := *s.cfg
	next.Storage.URL = "s3://new-bucket/team"
	target := newMemRegistry()
	calls := 0
	failing := storagetest.Wrap(target, storagetest.Hooks{Publish: func(ctx context.Context, next storage.Store, o storage.Object) error {
		calls++
		if calls == 2 {
			return errors.New("synthetic copy failure")
		}
		return next.Publish(ctx, o)
	}})
	if err := a.migrateStorage(ctx, s, failing, &next); err == nil {
		t.Fatal("copy succeeded")
	}
	cfg, err := a.loadProject()
	if err != nil || cfg.Storage != s.cfg.Storage {
		t.Fatalf("config changed: %+v %v", cfg, err)
	}
	if err := a.migrateStorage(ctx, s, target, &next); err != nil {
		t.Fatal(err)
	}
}

func TestMigrateStorageRefusesSourceChanges(t *testing.T) {
	a := migrationApp(t)
	ctx := context.Background()
	s, err := a.openSession(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	next := *s.cfg
	next.Storage.URL = "s3://new-bucket/team"
	changed := false
	target := storagetest.Wrap(newMemRegistry(), storagetest.Hooks{Publish: func(ctx context.Context, next storage.Store, o storage.Object) error {
		if !changed {
			changed = true
			if err := a.EditSecret(ctx, "default", "KEY", "third"); err != nil {
				return err
			}
		}
		return next.Publish(ctx, o)
	}})
	if err := a.migrateStorage(ctx, s, target, &next); !apperr.Is(err, apperr.CodeInvalidArgument) {
		t.Fatalf("got %v", err)
	}
	cfg, err := a.loadProject()
	if err != nil || cfg.Storage != s.cfg.Storage {
		t.Fatalf("config changed: %+v %v", cfg, err)
	}
}

func TestWriteConfigCannotBypassStorageMigration(t *testing.T) {
	a := migrationApp(t)
	cfg, err := a.loadProject()
	if err != nil {
		t.Fatal(err)
	}
	cfg.Storage.URL = "s3://another-bucket/team"
	data, err := config.MarshalProject(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.WriteConfig(string(data)); !apperr.Is(err, apperr.CodeConfigProtected) {
		t.Fatalf("got %v", err)
	}
}

func TestMigrateStorageRejectsCorruptCopy(t *testing.T) {
	a := migrationApp(t)
	ctx := context.Background()
	s, err := a.openSession(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	next := *s.cfg
	next.Storage.URL = "s3://new-bucket/team"
	target := storagetest.Wrap(newMemRegistry(), storagetest.Hooks{OpenPayload: func(context.Context, storage.Store, storage.Kind, string, digest.Digest) (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader([]byte("corrupted"))), nil
	}})
	if err := a.migrateStorage(ctx, s, target, &next); !apperr.Is(err, apperr.CodeUntrusted) {
		t.Fatalf("got %v", err)
	}
	cfg, err := a.loadProject()
	if err != nil || cfg.Storage != s.cfg.Storage {
		t.Fatalf("config changed: %+v %v", cfg, err)
	}
}

func TestMigrateStorageRefusesAnotherWorkspace(t *testing.T) {
	a := migrationApp(t)
	other := migrationApp(t)
	ctx := context.Background()
	s, err := a.openSession(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	next := *s.cfg
	next.Storage.URL = "s3://new-bucket/team"
	if err := a.migrateStorage(ctx, s, other.Storage, &next); !apperr.Is(err, apperr.CodeInvalidArgument) {
		t.Fatalf("got %v", err)
	}
}
