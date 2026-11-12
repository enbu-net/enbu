package cli

import (
	"bytes"
	"github.com/enbu-net/enbu/pkg/apperr"
	"github.com/enbu-net/enbu/pkg/config"
	"path/filepath"
	"strings"
	"testing"
)

func TestStorageMigrateRequiresPausedWrites(t *testing.T) {
	a, _ := newSeededApp(t, map[string]string{"KEY": "secret"})
	cmd := NewWithApp("test", a)
	cmd.SetArgs([]string{"storage", "migrate", "s3://bucket/team"})
	if err := cmd.Execute(); !apperr.Is(err, apperr.CodeInvalidArgument) {
		t.Fatalf("got %v", err)
	}
}
func TestStorageMigrateCopiesAndPersistsDestination(t *testing.T) {
	a, _ := newSeededApp(t, map[string]string{"KEY": "secret"})
	url := "local:///" + strings.TrimPrefix(filepath.ToSlash(t.TempDir()), "/")
	cmd := NewWithApp("test", a)
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"storage", "migrate", url, "--writes-paused", "--json"})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.LoadProjectFrom(a.RepositoryDir)
	if err != nil || cfg.Storage.URL != url {
		t.Fatalf("config %+v %v", cfg, err)
	}
	if !strings.Contains(out.String(), `"ok":true`) {
		t.Fatalf("output %s", out.String())
	}
}
