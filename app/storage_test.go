package app

import (
	"context"
	"fmt"
	"testing"

	"github.com/enbu-net/enbu/pkg/apperr"
	"github.com/enbu-net/enbu/pkg/config"
	"github.com/enbu-net/enbu/pkg/storage"
	"github.com/enbu-net/enbu/pkg/storage/storagetest"
	"github.com/opencontainers/go-digest"
)

func TestStorageURLValidation(t *testing.T) {
	a := &App{}
	for _, raw := range []string{"", "https://example.com", "local://host/tmp/store", "local:relative", "local:///tmp/store?x=1", "s3://user:password@bucket", "oci://example.com/repo:tag"} {
		t.Run(raw, func(t *testing.T) {
			if _, err := a.openStorage(context.Background(), &config.ProjectConfig{Storage: config.StorageConfig{URL: raw}}); err == nil {
				t.Fatalf("accepted %q", raw)
			}
		})
	}
}

func TestS3StorageConfiguration(t *testing.T) {
	a := &App{}
	cfg := &config.ProjectConfig{Storage: config.StorageConfig{
		URL: "s3://enbu-test/team/workspace/", Endpoint: "http://localhost:9000", Region: "us-east-1", PathStyle: true,
	}}
	store, err := a.openStorage(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if store == nil {
		t.Fatal("no S3 store")
	}
	cfg.Storage.Endpoint = "https://example.com/path"
	if _, err := a.openStorage(context.Background(), cfg); !apperr.Is(err, apperr.CodeInvalidArgument) {
		t.Fatalf("invalid S3 endpoint: %v", err)
	}
}

func TestHistoryOrdersRapidUpdates(t *testing.T) {
	ctx := context.Background()
	a := &App{Storage: newMemRegistry(), Identities: newMemKeyStore()}
	prepareApp(t, a, "default")
	if _, err := a.InitializeRepository(ctx); err != nil {
		t.Fatal(err)
	}
	if err := a.AddSecret(ctx, "default", "KEY", "0"); err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= 5; i++ {
		if err := a.EditSecret(ctx, "default", "KEY", fmt.Sprint(i)); err != nil {
			t.Fatal(err)
		}
	}
	entries, err := a.ListHistory(ctx, "default")
	if err != nil || len(entries) != 6 {
		t.Fatalf("%+v %v", entries, err)
	}
	if err := a.RestoreHistory(ctx, "default", 1); err != nil {
		t.Fatal(err)
	}
	secrets, err := a.ListSecrets(ctx, "default")
	if err != nil || secrets["KEY"] != "0" {
		t.Fatalf("%v %v", secrets, err)
	}
}

func TestInitializeRejectsCorruptControl(t *testing.T) {
	ctx := context.Background()
	a := &App{Storage: newMemRegistry(), Identities: newMemKeyStore()}
	prepareApp(t, a, "default")
	if _, err := a.InitializeRepository(ctx); err != nil {
		t.Fatal(err)
	}
	cfg, err := a.loadProject()
	if err != nil {
		t.Fatal(err)
	}
	genesis := digest.Digest(cfg.ControlGenesis)
	// The genesis object now holds bytes that are not that control.
	a.Storage = storagetest.Wrap(a.Storage, storagetest.Hooks{
		Fetch: func(ctx context.Context, next storage.Store, kind storage.Kind, scope string, rev digest.Digest) (storage.Object, error) {
			if kind == storage.KindControl && rev == genesis {
				return storage.Object{Kind: kind, Rev: rev, Signed: []byte("corrupt")}, nil
			}
			return next.Fetch(ctx, kind, scope, rev)
		},
	})
	if _, err := a.InitializeRepository(ctx); err == nil {
		t.Fatal("corrupt storage treated as successful initialization")
	}
}

// A repository with no trusted genesis must not adopt a workspace that storage
// already holds: nothing there says whose it is.
func TestInitializeRefusesAStorageThatAlreadyHoldsAWorkspace(t *testing.T) {
	ctx := context.Background()
	a := &App{Storage: newMemRegistry(), Identities: newMemKeyStore()}
	prepareApp(t, a, "default")
	if _, err := a.InitializeRepository(ctx); err != nil {
		t.Fatal(err)
	}
	other := &App{Storage: a.Storage, Identities: newMemKeyStore()}
	prepareApp(t, other, "default") // same workspace id, but no control_genesis
	if _, err := other.InitializeRepository(ctx); !apperr.Is(err, apperr.CodeIncompatibleStorage) {
		t.Fatalf("adopting an existing workspace without a genesis: %v", err)
	}
}
