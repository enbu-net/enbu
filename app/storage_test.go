package app

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/enbu-net/enbu/pkg/apperr"
	"github.com/enbu-net/enbu/pkg/config"
	"github.com/enbu-net/enbu/pkg/storage"
	"github.com/enbu-net/enbu/pkg/wsp"
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
	if store.Blobs == nil || store.Refs == nil {
		t.Fatalf("unexpected S3 configuration: %+v", store)
	}
	cfg.Storage.Endpoint = "https://example.com/path"
	if _, err := a.openStorage(context.Background(), cfg); !apperr.Is(err, apperr.CodeInvalidArgument) {
		t.Fatalf("invalid S3 endpoint: %v", err)
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
		prefix, id, _ := strings.Cut(strings.TrimPrefix(tag, snapshotPrefix(env)), "-")
		for _, nonCanonical := range []string{strings.ReplaceAll(id, "-", ""), "{" + id + "}", "urn:uuid:" + id} {
			if IsSnapshotTag(env, snapshotPrefix(env)+prefix+"-"+nonCanonical) {
				t.Fatalf("accepted non-canonical snapshot UUID %q", nonCanonical)
			}
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
	for _, kind := range []string{"control", "secrets"} {
		t.Run(kind, func(t *testing.T) {
			ctx := context.Background()
			a := &App{Storage: newMemRegistry(), Identities: newMemKeyStore()}
			prepareApp(t, a, "default")
			if _, err := a.InitializeRepository(ctx); err != nil {
				t.Fatal(err)
			}
			if err := a.AddSecret(ctx, "default", "KEY", "value"); err != nil {
				t.Fatal(err)
			}
			key := wsp.ControlRef
			if kind == "secrets" {
				key = secretsTag("default")
			}
			_, version, err := getRef(ctx, a.Storage, key)
			if err != nil && !errors.Is(err, storage.ErrNotFound) {
				t.Fatal(err)
			}
			if err := putRef(ctx, a.Storage, key, []byte("corrupt"), version); err != nil {
				t.Fatal(err)
			}
			if _, err := a.InitializeRepository(ctx); err == nil {
				t.Fatal("corrupt storage treated as successful initialization")
			}
		})
	}
}
