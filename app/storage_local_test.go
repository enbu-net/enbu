//go:build fixture

package app

import (
	"context"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"uuid"

	"github.com/enbu-net/enbu/pkg/apperr"
	"github.com/enbu-net/enbu/pkg/config"
)

func TestLocalStorageNativePath(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "objects with spaces")
	path := "/" + strings.TrimPrefix(filepath.ToSlash(dir), "/")
	raw := (&url.URL{Scheme: "local", Path: path}).String()
	a := &App{}
	store, err := a.openStorage(context.Background(), &config.ProjectConfig{Storage: config.StorageConfig{URL: raw}})
	if err != nil {
		t.Fatal(err)
	}
	if err := putRef(context.Background(), store, "probe", []byte("x"), ""); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "refs", "probe")); err != nil {
		t.Fatalf("storage did not use local directory %q: %v", dir, err)
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
	if id, err := uuid.Parse(initialized.WorkspaceID); err != nil || id.String() != initialized.WorkspaceID {
		t.Fatalf("invalid initialized workspace ID: %+v, %v", initialized, err)
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
