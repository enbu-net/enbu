package cli

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/enbu-net/enbu/app"
	"github.com/enbu-net/enbu/pkg/config"
	"github.com/enbu-net/enbu/pkg/storage/storagetest"
)

func TestGHCRAccessHint(t *testing.T) {
	founded := &app.InitResult{Storage: "oci://ghcr.io/enbu-net/app-enbu", Founded: true}
	if hint := ghcrAccessHint(founded); !strings.Contains(hint, "app-enbu") || !strings.Contains(hint, "Inherit access from repository") {
		t.Fatalf("hint for a new GHCR workspace: %q", hint)
	}
	for _, result := range []*app.InitResult{
		{Storage: "oci://ghcr.io/enbu-net/app-enbu"},                    // joined, not founded
		{Storage: "oci://registry.example.com/team/app", Founded: true}, // not GHCR
		{Storage: "s3://bucket/team", Founded: true},
	} {
		if hint := ghcrAccessHint(result); hint != "" {
			t.Errorf("%+v: unexpected hint %q", result, hint)
		}
	}
}

func TestInitWithoutGitDefaultsToSignedInGHCR(t *testing.T) {
	a, _ := newSeededApp(t, nil)
	a.RepositoryDir = filepath.Join(t.TempDir(), "project")
	if err := os.MkdirAll(a.RepositoryDir, 0700); err != nil {
		t.Fatal(err)
	}
	a.RepoDetector = noGitRepo{}
	a.Storage = storagetest.NewMemory()
	cmd := NewWithApp("test", a)
	cmd.SetOut(io.Discard)
	cmd.SetArgs([]string{"init"})
	if err := cmd.ExecuteContext(context.Background()); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.LoadProjectFrom(a.RepositoryDir)
	if err != nil || cfg.Storage.URL != "oci://ghcr.io/alice/project-enbu" {
		t.Fatalf("config %+v %v", cfg, err)
	}
}

type noGitRepo struct{}

func (noGitRepo) LoadRepo() (string, string, error) { return "", "", errors.New("no git") }
