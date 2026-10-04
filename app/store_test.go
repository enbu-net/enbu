package app

import (
	"context"
	"errors"
	"testing"

	"github.com/enbu-net/enbu/pkg/storage"
	"github.com/opencontainers/go-digest"
)

func TestHistorySnapshotReusesSecretsBlob(t *testing.T) {
	ctx := context.Background()
	a := newTestApp(t, "owner", "repo", "default", mustKeyPair(t), nil)
	if err := a.AddSecret(ctx, "default", "KEY", "value"); err != nil {
		t.Fatal(err)
	}
	current, _, err := a.Storage.Refs.Get(ctx, secretsTag("default"))
	if err != nil {
		t.Fatal(err)
	}
	snapshots, err := a.Storage.Refs.List(ctx, snapshotPrefix("default"))
	if err != nil || len(snapshots) != 1 {
		t.Fatalf("snapshots=%v %v", snapshots, err)
	}
	snapshot, _, err := a.Storage.Refs.Get(ctx, snapshots[0])
	if err != nil || snapshot != current {
		t.Fatalf("snapshot points at %s, want the secrets blob %s (%v)", snapshot, current, err)
	}
}

func TestGetRefDoesNotReportDanglingRefAsMissing(t *testing.T) {
	ctx := context.Background()
	store := storage.NewLocal(t.TempDir())
	if err := store.Refs.Put(ctx, "dangling", digest.FromString("never stored"), ""); err != nil {
		t.Fatal(err)
	}
	_, _, err := getRef(ctx, store, "dangling")
	if err == nil || errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("dangling ref error = %v, want a non-NotFound error", err)
	}
	if _, _, err := getRef(ctx, store, "absent"); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("absent ref error = %v, want ErrNotFound", err)
	}
}
