package cli

import (
	"github.com/enbu-net/enbu/app"
	"github.com/enbu-net/enbu/pkg/config"
	"testing"
)

const testWorkspaceID = "11111111-1111-4111-8111-111111111111"

func workspaceObject() []byte {
	return []byte(testWorkspaceID)
}
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
