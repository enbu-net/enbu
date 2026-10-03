package app

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"github.com/enbu-net/enbu/pkg/apperr"
	"github.com/enbu-net/enbu/pkg/config"
	"github.com/enbu-net/enbu/pkg/storage"
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

func TestLocalWorkspaceWithoutGitHub(t *testing.T) {
	ctx := context.Background()
	a := &App{RepositoryDir: t.TempDir(), Identities: &memKeyStore{data: make(map[string][]byte)}}
	path := "/" + strings.TrimPrefix(filepath.ToSlash(t.TempDir()), "/")
	a.StorageURL = (&url.URL{Scheme: "local", Path: path}).String()
	initialized, err := a.InitializeRepository(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if initialized.WorkspaceID == "" {
		t.Fatalf("%+v", initialized)
	}
	if err := a.AddSecret(ctx, "default", "API_KEY", "secret"); err != nil {
		t.Fatal(err)
	}
	secrets, err := a.ListSecrets(ctx, "default")
	if err != nil || secrets["API_KEY"] != "secret" {
		t.Fatalf("%v %v", secrets, err)
	}
	cfg, err := config.LoadProjectFrom(a.RepositoryDir)
	if err != nil {
		t.Fatal(err)
	}
	cfg.WorkspaceID = "11111111-1111-4111-8111-111111111111"
	if err := config.SaveProjectTo(a.RepositoryDir, cfg); err != nil {
		t.Fatal(err)
	}
	if _, err := a.ListSecrets(ctx, "default"); !apperr.Is(err, apperr.CodeInvalidArgument) {
		t.Fatalf("workspace mismatch: %v", err)
	}
}

func TestSnapshotKeysAreUnambiguousAndFitOCI(t *testing.T) {
	for _, env := range []string{"dev", "dev-123", strings.Repeat("a", 100)} {
		tag := snapshotTag(env)
		if err := storage.ValidateKey(tag); err != nil {
			t.Fatal(err)
		}
		if !IsSnapshotTag(env, tag) {
			t.Fatal(tag)
		}
		for _, other := range []string{"prod", env + "-123"} {
			if IsSnapshotTag(other, tag) {
				t.Fatalf("%s belongs to %s", tag, other)
			}
		}
		if IsSnapshotTag(env, tag+"-garbage") {
			t.Fatal("accepted malformed UUID")
		}
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

func TestInitializeRejectsCorruptStorageRecords(t *testing.T) {
	for _, kind := range []string{"recipient", "secrets"} {
		t.Run(kind, func(t *testing.T) {
			ctx := context.Background()
			a := &App{Storage: newMemRegistry(), Identities: newMemKeyStore()}
			prepareApp(t, a, "default")
			initialized, err := a.InitializeRepository(ctx)
			if err != nil {
				t.Fatal(err)
			}
			key := RecipientKey(initialized.PublicKey)
			media := recipientMediaType
			if kind == "secrets" {
				key = secretsTag("default")
				media = secretsMediaType
			}
			_, version, err := a.Storage.Get(ctx, key)
			if err != nil && !errors.Is(err, storage.ErrNotFound) {
				t.Fatal(err)
			}
			if err := a.Storage.Put(ctx, key, storage.Object{MediaType: media, Data: []byte{}}, version); err != nil {
				t.Fatal(err)
			}
			if _, err := a.InitializeRepository(ctx); err == nil {
				t.Fatal("corrupt storage treated as successful initialization")
			}
		})
	}
}
