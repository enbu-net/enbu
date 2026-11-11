package desktop

import (
	"context"
	"errors"
	"testing"

	"github.com/enbu-net/enbu/app"
	"github.com/enbu-net/enbu/pkg/clock"
	"github.com/enbu-net/enbu/pkg/config"
	gitprovider "github.com/enbu-net/enbu/pkg/provider/git"
)

type cancelingInspector struct{ cancel context.CancelFunc }

func (g cancelingInspector) Inspect(_ context.Context, path string) (gitprovider.Repository, error) {
	g.cancel()
	return gitprovider.Repository{Root: path}, nil
}

func TestCanceledSelectionDoesNotPersist(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	a := app.New(clock.New())
	a.RepositoryDir = t.TempDir()
	original := a.RepositoryDir
	a.Git = cancelingInspector{cancel}
	s := NewService(a)
	s.ctx = ctx
	if _, err := s.SelectRepository(t.TempDir()); err == nil {
		t.Fatalf("selection error = %v", err)
	}
	if a.RepositoryDir != original {
		t.Fatal("canceled selection changed application workspace")
	}
	gui, err := config.LoadGUI()
	if err == nil && gui.SelectedRepo != "" {
		t.Fatal("canceled selection persisted a workspace")
	}
}

func TestCanceledRepositoryCallDoesNotRun(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	s := NewService(app.New(clock.New()))
	s.ctx = ctx
	original := s.app.RepositoryDir
	cancel()
	called := false
	_, err := withRepoPathResult(s, t.TempDir(), func() (int, error) {
		called = true
		return 1, nil
	})
	if !errors.Is(err, context.Canceled) || called || s.app.RepositoryDir != original {
		t.Fatalf("canceled call: called=%t err=%v", called, err)
	}
}

func TestCanceledRemovalPreservesSelection(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	path := t.TempDir()
	if err := config.SaveGUI(&config.GUIConfig{SelectedRepo: path, RepoHistory: []string{path}}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	s := NewService(app.New(clock.New()))
	s.ctx = ctx
	cancel()
	if err := s.RemoveRepository(path); err == nil {
		t.Fatalf("removal error = %v", err)
	}
	gui, err := config.LoadGUI()
	if err != nil || gui.SelectedRepo != path || len(gui.RepoHistory) != 1 {
		t.Fatalf("canceled removal changed selection: %+v err=%v", gui, err)
	}
}
