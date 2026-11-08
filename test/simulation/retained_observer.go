package simulation

import (
	"context"
	"fmt"
	"maps"
	"os"
	"reflect"
	"slices"

	"github.com/enbu-net/enbu/pkg/apperr"
	"github.com/enbu-net/enbu/pkg/config"
	"github.com/enbu-net/enbu/pkg/storage"
	"github.com/opencontainers/go-digest"
)

// RetainedObserver checks that a branch one observer read before its author's
// removal, but the removing admin never saw, is set aside like any head of a
// removed author: the observer agrees with every other device, sees no
// rollback, and the branch is not revived by the author's readmission.
func (w *World) RetainedObserver(ctx context.Context, cold bool) error {
	if len(w.Devices) < 3 {
		return fmt.Errorf("retained observer needs three devices")
	}
	cfg, err := config.LoadProjectFrom(w.Devices[0].App.RepositoryDir)
	if err != nil {
		return err
	}
	scope := storage.StateScope(cfg.WorkspaceID, cfg.Resource("default"))
	list := func() ([]digest.Digest, error) { return w.Devices[2].Store.Discover(ctx, storage.KindState, scope) }
	before := maps.Clone(w.Model["default"])
	before["K0"], before["K1"], before["UNRELATED"] = "resolved", "original", "kept"
	if _, err := w.Devices[0].App.ImportSecrets(ctx, "default", before, true); err != nil {
		return err
	}
	w.Model["default"] = maps.Clone(before)
	if err := w.Check(ctx, "default"); err != nil {
		return err
	}
	refs, err := list()
	if err != nil {
		return err
	}
	if err := w.Devices[2].App.SyncSecrets(ctx, "default"); err != nil {
		return err
	}
	after, err := list()
	if err != nil {
		return err
	}
	var added []digest.Digest
	for _, ref := range after {
		if !slices.Contains(refs, ref) {
			added = append(added, ref)
		}
	}
	if len(added) != 1 {
		return fmt.Errorf("synchronizer published %d branches", len(added))
	}
	retired := added[0]
	got, err := w.Devices[1].App.ListSecrets(ctx, "default")
	if err != nil || !reflect.DeepEqual(got, before) {
		return fmt.Errorf("observer did not accept pre-removal snapshot: %v", err)
	}
	// The founder has not accepted this otherwise valid publication. Its
	// temporary network view omits only that State, never the Control DAG.
	original := w.Devices[0].Store.Store
	w.Devices[0].Store.Store = hideObserverRevisions(original, storage.KindState, scope, []digest.Digest{retired})
	err = w.Devices[0].App.RemoveMember(ctx, w.Devices[2].ID)
	w.Devices[0].Store.Store = original
	if err != nil {
		return err
	}
	got, err = w.Devices[2].App.ListSecrets(ctx, "default")
	if requireCode(err, apperr.CodeNotMember) != nil || got != nil {
		return fmt.Errorf("removed synchronizer retained read authority: %v", err)
	}
	if _, err := w.Devices[2].App.InitializeRepository(ctx); err != nil {
		return err
	}
	if err := w.Devices[0].App.ApproveMember(ctx, w.Devices[2].ID); err != nil {
		return err
	}
	if err := w.Devices[0].App.EditSecret(ctx, "default", "K0", "original"); err != nil {
		return err
	}
	refs, err = list()
	if err != nil {
		return err
	}
	results, err := w.runDeviceBatch(ctx, "publish", []int{0, 2}, []func(int) error{
		func(i int) error { return w.Devices[i].App.DeleteSecret(ctx, "default", "K0") },
		func(i int) error {
			_, err := w.Devices[i].App.ImportSecrets(ctx, "default", map[string]string{"K1": "right"}, true)
			return err
		},
	})
	if err != nil {
		return err
	}
	for _, result := range results {
		if result != nil {
			return fmt.Errorf("current-author edit failed: %w", result)
		}
	}
	after, err = list()
	if err != nil {
		return err
	}
	var current []digest.Digest
	for _, ref := range after {
		if !slices.Contains(refs, ref) {
			current = append(current, ref)
		}
	}
	if len(current) != 2 {
		return fmt.Errorf("current writers published %d branches", len(current))
	}
	want := maps.Clone(before)
	delete(want, "K0")
	want["K1"] = "right"
	if cold {
		if err := os.RemoveAll(w.Devices[1].App.CacheDir); err != nil {
			return err
		}
		w.Restart(1)
	}
	// Every device, the observer that read the retired branch included, reads
	// the two current heads.
	for i, d := range w.Devices {
		got, err := d.App.ListSecrets(ctx, "default")
		if err != nil || !reflect.DeepEqual(got, want) {
			return fmt.Errorf("observer %d disagreed: %v", i, err)
		}
	}
	set, err := w.Devices[1].App.ListConflicts(ctx, "default")
	if err != nil {
		return err
	}
	expectedHeads := []string{current[0].Encoded(), current[1].Encoded()}
	slices.Sort(expectedHeads)
	if !slices.Equal(set.Heads, expectedHeads) || len(set.Conflicts) != 0 {
		return fmt.Errorf("observer kept the retired branch: %+v (retired %s)", set, retired.Encoded())
	}
	w.Model["default"] = want
	if err := w.Check(ctx, "default"); err != nil {
		return err
	}
	for i := range w.Devices {
		w.Restart(i)
		members, err := w.Devices[i].App.ListMembers(ctx)
		if err != nil {
			return err
		}
		expectedMembers := map[string]bool{}
		for j, d := range w.Devices {
			expectedMembers[d.ID] = j == 0
		}
		actualMembers := map[string]bool{}
		for _, member := range members {
			actualMembers[member.DeviceID] = member.Admin
		}
		if !reflect.DeepEqual(actualMembers, expectedMembers) {
			return fmt.Errorf("retained branch changed membership or admin roles")
		}
		key := fmt.Sprintf("AFTER_RETAINED_%d", i)
		if err := w.Devices[i].App.AddSecret(ctx, "default", key, "acknowledged"); err != nil {
			return err
		}
		w.Model["default"][key] = "acknowledged"
	}
	return w.Check(ctx, "default")
}
