package simulation

import (
	"context"
	"fmt"
	"strings"

	"github.com/enbu-net/enbu/pkg/apperr"
	"github.com/enbu-net/enbu/pkg/config"
)

func (w *World) RejectedEdits(ctx context.Context) error {
	for _, d := range w.Devices {
		// The retained history has exactly one version. Bad indexes must not
		// publish anything, alter a checkpoint, or clear the existing secret map.
		for _, index := range []int{-1, 0, 2, 1 << 30} {
			_, err := d.App.DiffHistory(ctx, "default", index, 1)
			if check := requireCode(err, apperr.CodeInvalidArgument); check != nil {
				return check
			}
			if err := w.Tape.Observe("invalid-diff", index, ErrorCode(err)); err != nil {
				return err
			}
			err = d.App.RestoreHistory(ctx, "default", index)
			if check := requireCode(err, apperr.CodeInvalidArgument); check != nil {
				return check
			}
			if err := w.Tape.Observe("invalid-restore", index, ErrorCode(err)); err != nil {
				return err
			}
		}
		original, err := d.App.ReadConfig()
		if err != nil {
			return err
		}
		cfg, err := config.LoadProjectFrom(d.App.RepositoryDir)
		if err != nil {
			return err
		}
		for _, change := range []struct{ key, old, replacement string }{
			{"workspace", cfg.WorkspaceID, "00000000-0000-4000-8000-000000000000"},
			{"genesis", cfg.ControlGenesis, "sha256:" + strings.Repeat("0", 64)},
			{"incarnation", cfg.Environments["default"].Incarnation, "00000000-0000-4000-8000-000000000001"},
		} {
			if change.old == "" {
				return fmt.Errorf("protected fixture %s missing", change.key)
			}
			edited := strings.Replace(original, change.old, change.replacement, 1)
			err := d.App.WriteConfig(edited)
			if check := requireCode(err, apperr.CodeConfigProtected); check != nil {
				return fmt.Errorf("%s: %w", change.key, check)
			}
			restored, err := d.App.ReadConfig()
			if err != nil {
				return err
			}
			if restored != original {
				return fmt.Errorf("rejected %s edit modified configuration", change.key)
			}
		}
	}
	return w.Check(ctx, "default")
}
