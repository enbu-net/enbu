package simulation

import (
	"context"
	"fmt"
	"sort"

	"github.com/enbu-net/enbu/pkg/apperr"
)

// GeneratedTeamGroup preserves the workload's existing model. A continuing
// developer writes while an admin removes the synchronizing third device.
// Only that device's success or authorization rejection is schedule-dependent;
// the continuing developer's acknowledged write is never optional.
func (w *World) GeneratedTeamGroup(ctx context.Context, key, value string) error {
	if len(w.Devices) < 3 {
		return fmt.Errorf("team group requires three devices")
	}
	target := len(w.Devices) - 1
	results, err := w.runDeviceBatch(ctx, "publish", []int{0, 1, target}, []func(int) error{
		func(int) error { return w.Devices[0].App.RemoveMember(ctx, w.Devices[target].ID) },
		func(int) error { return w.Devices[1].App.AddSecret(ctx, "default", key, value) },
		func(int) error { return w.Devices[target].App.SyncSecrets(ctx, "default") },
	})
	if err != nil {
		return err
	}
	if results[0] != nil || results[1] != nil {
		return fmt.Errorf("continuing team operation failed: %v", results)
	}
	if results[2] != nil && ErrorCode(results[2]) != string(apperr.CodeNotMember) {
		return fmt.Errorf("removed synchronizer: %w", results[2])
	}
	w.Model["default"][key] = value
	if err := requireCode(w.Devices[target].App.AddSecret(ctx, "default", "REMOVED_WRITE", "must-not-commit"), apperr.CodeNotMember); err != nil {
		return err
	}
	// Removal must deny every live environment, not just the one being edited.
	names := make([]string, 0, len(w.Model))
	for env := range w.Model {
		names = append(names, env)
	}
	sort.Strings(names)
	for _, env := range names {
		if _, err := w.Devices[target].App.ListSecrets(ctx, env); requireCode(err, apperr.CodeNotMember) != nil {
			return fmt.Errorf("removed device read %s: %v", env, err)
		}
	}
	w.Restart(target)
	if _, err := w.Devices[target].App.InitializeRepository(ctx); err != nil {
		return err
	}
	if err := w.Devices[0].App.ApproveMember(ctx, w.Devices[target].ID); err != nil {
		return err
	}
	if err := w.Devices[0].App.SyncSecrets(ctx, "default"); err != nil {
		return err
	}
	return w.Check(ctx, "default")
}
