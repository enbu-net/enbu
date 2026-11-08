package simulation

import (
	"context"
	"fmt"
	"maps"
	"os"
	"reflect"
	"slices"

	"github.com/enbu-net/enbu/app"
	"github.com/enbu-net/enbu/pkg/apperr"
	"github.com/enbu-net/enbu/pkg/config"
	"github.com/enbu-net/enbu/pkg/storage"
	"github.com/opencontainers/go-digest"
)

// RetainedObserver distinguishes independently accepted pre-removal branches
// from current-author heads. Equal snapshots need not have equal ancestry.
func (w *World) RetainedObserver(ctx context.Context, cold, deleteChoice bool) error {
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
	// Observers that never accepted the old author's branch use the two
	// current heads. The continuing observer must preserve its accepted head.
	for i, d := range w.Devices {
		if i == 1 {
			continue
		}
		got, err := d.App.ListSecrets(ctx, "default")
		if err != nil || !reflect.DeepEqual(got, want) {
			return fmt.Errorf("unexposed observer %d disagreed: %v", i, err)
		}
	}
	if cold {
		if err := os.RemoveAll(w.Devices[1].App.CacheDir); err != nil {
			return err
		}
		w.Restart(1)
	}
	observer := w.Devices[1].App
	mark := len(w.Tape.Recording.Entries)
	if w.Tape.Replay {
		mark = w.Tape.cursor
	}
	got, err = observer.ListSecrets(ctx, "default")
	if requireCode(err, apperr.CodeSecretConflict) != nil || got != nil {
		return fmt.Errorf("retained observer hid competing values: %v", err)
	}
	set, err := observer.ListConflicts(ctx, "default")
	if err != nil {
		return err
	}
	expectedHeads := []string{retired.Encoded(), current[0].Encoded(), current[1].Encoded()}
	slices.Sort(expectedHeads)
	if !slices.Equal(set.Heads, expectedHeads) || len(set.Conflicts) != 1 || set.Conflicts[0].Key != "K0" {
		return fmt.Errorf("retained observer lost exact heads/conflict: %+v", set)
	}
	expectedCandidates := map[app.ConflictCandidate]bool{{Value: "resolved"}: true, {Value: "original"}: true, {Deleted: true}: true}
	candidates := map[app.ConflictCandidate]bool{}
	for _, c := range set.Conflicts[0].Candidates {
		candidates[c] = true
	}
	if len(set.Conflicts[0].Candidates) != 3 || !reflect.DeepEqual(candidates, expectedCandidates) {
		return fmt.Errorf("retained observer candidates %v want %v", candidates, expectedCandidates)
	}
	for _, call := range []func() error{
		func() error { return observer.AddSecret(ctx, "default", "MUST_NOT_ACK", "blocked") },
		func() error { return observer.SyncSecrets(ctx, "default") },
	} {
		if err := requireCode(call(), apperr.CodeSecretConflict); err != nil {
			return err
		}
	}
	choice := app.SecretChoice{Value: "team-choice", Delete: deleteChoice}
	choices := map[string]app.SecretChoice{"K0": choice}
	if err := requireCode(observer.ResolveSecrets(ctx, "default", set.Heads[:2], choices), apperr.CodeConflict); err != nil {
		return err
	}
	end := len(w.Tape.Recording.Entries)
	if w.Tape.Replay {
		end = w.Tape.cursor
	}
	if err := requireReadOnlyStorage(w.Tape.Recording.Entries[mark:end]); err != nil {
		return err
	}
	if err := observer.ResolveSecrets(ctx, "default", set.Heads, choices); err != nil {
		return err
	}
	if !deleteChoice {
		want["K0"] = "team-choice"
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
