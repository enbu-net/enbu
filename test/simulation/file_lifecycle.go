package simulation

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"

	"github.com/enbu-net/enbu/app"
	"github.com/enbu-net/enbu/pkg/schema/secretmap"
)

// fileLifecycle verifies the data written to disk, not merely a successful
// return. A local-only variable must never accidentally enter shared storage.
func (w *World) fileLifecycle(ctx context.Context) error {
	a, b := w.Devices[0].App, w.Devices[1].App
	path := filepath.Join(a.RepositoryDir, ".env")
	if err := os.WriteFile(path, []byte("BASE=old\nLOCAL_ONLY=mine\n"), 0600); err != nil {
		return err
	}
	if err := b.AddSecret(ctx, "default", "TOKEN", "revoked"); err != nil {
		return err
	}
	if _, err := a.PullSecretsToFileWith(ctx, "default", false); err != nil {
		return err
	}
	if err := b.DeleteSecret(ctx, "default", "TOKEN"); err != nil {
		return err
	}
	want := map[string]string{"BASE": "original", "LOCAL_ONLY": "mine"}
	written, err := a.PullSecretsToFileWith(ctx, "default", false)
	if err != nil {
		return err
	}
	if err := checkWritten(written, []string{"LOCAL_ONLY"}, []string{"TOKEN"}); err != nil {
		return err
	}
	if err := w.checkOutput("marked-delete", path, want); err != nil {
		return err
	}
	// Old files without a marker need history to distinguish deleted secrets
	// from variables that were never shared. A deleted name stays enbu-owned
	// even when somebody has replaced its value by hand.
	if err := os.WriteFile(path, []byte("BASE=old\nTOKEN=handwritten\nLOCAL_ONLY=mine\n"), 0600); err != nil {
		return err
	}
	written, err = a.PullSecretsToFileWith(ctx, "default", false)
	if err != nil {
		return err
	}
	if err := checkWritten(written, []string{"LOCAL_ONLY"}, []string{"TOKEN"}); err != nil {
		return err
	}
	if err := w.checkOutput("unmarked-delete", path, want); err != nil {
		return err
	}
	if _, err := a.PullSecretsToFileWith(ctx, "default", false); err != nil {
		return err
	}
	if err := w.checkOutput("repeat", path, want); err != nil {
		return err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if strings.Count(string(data), "LOCAL_ONLY=") != 1 || strings.Count(string(data), "# Local variables below") != 1 {
		return fmt.Errorf("repeat pull duplicated local variables or marker")
	}
	written, err = a.PullSecretsToFileWith(ctx, "default", true)
	if err != nil {
		return err
	}
	if err := checkWritten(written, nil, nil); err != nil {
		return err
	}
	if err := w.checkOutput("replace", path, map[string]string{"BASE": "original"}); err != nil {
		return err
	}
	// A rejoining device cannot classify names held only by revisions that were
	// encrypted while it was absent. Keep those names instead of deleting them.
	if err := a.RemoveMember(ctx, w.Devices[1].ID); err != nil {
		return err
	}
	if err := a.AddSecret(ctx, "default", "HIDDEN", "old-secret"); err != nil {
		return err
	}
	if err := a.DeleteSecret(ctx, "default", "HIDDEN"); err != nil {
		return err
	}
	if _, err := b.InitializeRepository(ctx); err != nil {
		return err
	}
	if err := a.ApproveMember(ctx, w.Devices[1].ID); err != nil {
		return err
	}
	path = filepath.Join(b.RepositoryDir, ".env")
	if err := os.WriteFile(path, []byte("BASE=old\nHIDDEN=personal\nLOCAL_ONLY=mine\n"), 0600); err != nil {
		return err
	}
	written, err = b.PullSecretsToFileWith(ctx, "default", false)
	if err != nil {
		return err
	}
	if err := checkWritten(written, []string{"HIDDEN", "LOCAL_ONLY"}, nil); err != nil {
		return err
	}
	if err := w.checkOutput("unreadable-history", path, map[string]string{"BASE": "original", "HIDDEN": "personal", "LOCAL_ONLY": "mine"}); err != nil {
		return err
	}
	return w.Check(ctx, "default")
}

func checkWritten(got *app.WrittenFile, kept, removed []string) error {
	if got.Count != 1 || !reflect.DeepEqual(got.Kept, kept) || !reflect.DeepEqual(got.Removed, removed) {
		return fmt.Errorf("file summary: got %+v want kept %v removed %v", got, kept, removed)
	}
	return nil
}
func (w *World) checkOutput(label, path string, want map[string]string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	got, err := secretmap.ImportDotenv(data)
	if err != nil {
		return err
	}
	if err := w.Tape.Observe("output-file", []any{label, want}, got); err != nil {
		return err
	}
	if !reflect.DeepEqual(map[string]string(got), want) {
		return fmt.Errorf("%s: output got %v want %v", label, got, want)
	}
	return nil
}
