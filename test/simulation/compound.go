package simulation

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"slices"

	"github.com/enbu-net/enbu/app"
	"github.com/enbu-net/enbu/pkg/apperr"
	"github.com/enbu-net/enbu/pkg/wsp"
)

type CompoundCase struct{ Control, Fault, Resolution string }

// Compound crosses two independent forks with a disconnected observer and a
// failed resolution publication. Expected membership and candidates come from
// the operations in the fixture, never from an observed application result.
func (w *World) Compound(ctx context.Context, c CompoundCase) error {
	if !slices.Contains([]string{"remove-writer", "demote-admin"}, c.Control) || !slices.Contains([]string{"crash-before", "crash-after", "after"}, c.Fault) || !slices.Contains([]string{"same", "different", "delete"}, c.Resolution) {
		return fmt.Errorf("invalid compound case %+v", c)
	}
	ctx = wsp.WithSerialHeadReads(ctx)
	a, b := w.Devices[0].App, w.Devices[1].App
	if err := a.CreateEnvironment("production"); err != nil {
		return err
	}
	if err := w.Share(0); err != nil {
		return err
	}
	if err := a.AddSecret(ctx, "production", "SENTINEL", "production-only"); err != nil {
		return err
	}
	w.Model["production"] = map[string]string{"SENTINEL": "production-only"}
	if _, err := a.ImportSecrets(ctx, "default", map[string]string{"K": "original", "UNRELATED": "kept"}, true); err != nil {
		return err
	}
	w.Model["default"] = map[string]string{"K": "original", "UNRELATED": "kept"}
	if err := a.SetAdmin(ctx, w.Devices[1].ID, true); err != nil {
		return err
	}
	if err := w.Check(ctx, "default"); err != nil {
		return err
	}
	if err := w.Check(ctx, "production"); err != nil {
		return err
	}
	w.Devices[3].Store.Arm(Fault{Method: "*", Mode: "partition"})
	if _, err := w.Devices[3].App.ListSecrets(ctx, "default"); !errors.Is(err, ErrOffline) {
		return fmt.Errorf("compound observer was not partitioned: %v", err)
	}
	results, err := w.runDeviceBatch(ctx, "publish", []int{0, 2}, []func(int) error{
		func(i int) error { return w.Devices[i].App.EditSecret(ctx, "default", "K", "first-writer") },
		func(i int) error { return w.Devices[i].App.DeleteSecret(ctx, "default", "K") },
	})
	if err != nil {
		return err
	}
	for _, result := range results {
		if result != nil && ErrorCode(result) != string(apperr.CodeSecretConflict) {
			return result
		}
	}
	initial := map[app.ConflictCandidate]bool{{Value: "first-writer"}: true, {Deleted: true}: true}
	// Both admins accept the data heads before either changes membership. A
	// surviving admin must retain this accepted conflict even if its author leaves.
	for _, i := range []int{0, 1} {
		if err := w.compoundCandidates(ctx, i, initial); err != nil {
			return err
		}
	}
	left := func(int) error {
		if c.Control == "remove-writer" {
			return a.RemoveMember(ctx, w.Devices[2].ID)
		}
		return a.SetAdmin(ctx, w.Devices[1].ID, false)
	}
	results, err = w.runBatch(ctx, "publish", []func(int) error{
		left,
		func(int) error { return b.SetAdmin(ctx, w.Devices[3].ID, true) },
	})
	if err != nil {
		return err
	}
	for _, result := range results {
		code := ErrorCode(result)
		if code != "" && code != string(apperr.CodeControlForked) && code != string(apperr.CodeReencryptIncomplete) {
			return fmt.Errorf("compound control update: %w", result)
		}
	}
	// a is an admin of both heads, and so is b unless a demoted it; any other
	// device stays stopped until an admin of both joins the fork.
	stopped := []int{2}
	if c.Control == "demote-admin" {
		stopped = append(stopped, 1)
	}
	for _, i := range stopped {
		if _, err := w.Devices[i].App.ListSecrets(ctx, "default"); requireCode(err, apperr.CodeControlForked) != nil {
			return fmt.Errorf("control fork failed to block device %d: %v", i, err)
		}
		if err := requireCode(w.Devices[i].App.ResolveSecrets(ctx, "default", []string{"stale"}, []app.SecretChoice{{Key: "K", Value: "forbidden"}}), apperr.CodeControlForked); err != nil {
			return err
		}
	}
	// a's next operation joins the fork. Control resolution commits first; data
	// re-encryption must report the unresolved data conflict rather than
	// treating it as a successful full repair.
	if _, err := a.ListSecrets(ctx, "default"); requireCode(err, apperr.CodeReencryptIncomplete) != nil {
		return fmt.Errorf("joining the fork: %v", err)
	}
	members, err := a.ListMembers(ctx)
	if err != nil {
		return err
	}
	actual, expected := map[string]bool{}, map[string]bool{}
	for _, member := range members {
		actual[member.DeviceID] = member.Admin
	}
	for i, d := range w.Devices {
		if i == 2 && c.Control == "remove-writer" {
			continue
		}
		expected[d.ID] = i == 0 || (i == 1 && c.Control != "demote-admin")
	}
	if !reflect.DeepEqual(actual, expected) {
		return fmt.Errorf("compound membership got %v want %v", actual, expected)
	}
	if c.Control == "remove-writer" {
		if err := requireCode(w.Devices[2].App.AddSecret(ctx, "default", "FORBIDDEN", "x"), apperr.CodeNotMember); err != nil {
			return err
		}
		if _, err := w.Devices[2].App.ListSecrets(ctx, "production"); requireCode(err, apperr.CodeNotMember) != nil {
			return fmt.Errorf("removed writer could read second environment: %v", err)
		}
	}
	production, err := a.ListSecrets(ctx, "production")
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(production, w.Model["production"]) {
		return fmt.Errorf("compound control repair changed second environment: %v", production)
	}
	for _, i := range []int{0, 1} {
		if err := w.compoundCandidates(ctx, i, initial); err != nil {
			return err
		}
	}
	set, err := a.ListConflicts(ctx, "default")
	if err != nil {
		return err
	}
	rightChoice := app.SecretChoice{Key: "K", Value: "left-resolution"}
	switch c.Resolution {
	case "different":
		rightChoice.Value = "right-resolution"
	case "delete":
		rightChoice = app.SecretChoice{Key: "K", Delete: true}
	}
	w.Devices[1].Store.Arm(Fault{Method: "publish", At: 1, Mode: c.Fault})
	results, err = w.runBatch(ctx, "publish", []func(int) error{
		func(int) error {
			return a.ResolveSecrets(ctx, "default", slices.Clone(set.Heads), []app.SecretChoice{{Key: "K", Value: "left-resolution"}})
		},
		func(int) error {
			return catchCrash(func() error {
				return b.ResolveSecrets(ctx, "default", slices.Clone(set.Heads), []app.SecretChoice{rightChoice})
			})
		},
	})
	if err != nil {
		return err
	}
	if w.Devices[1].Store.faultHits != 1 {
		return fmt.Errorf("compound resolution fault was not injected exactly once")
	}
	w.Devices[1].Store.Arm(Fault{})
	if results[0] != nil {
		return fmt.Errorf("uninterrupted resolver: %w", results[0])
	}
	if !errors.Is(results[1], ErrOffline) && !errors.Is(results[1], ErrCrash) {
		return fmt.Errorf("interrupted resolver: expected injected failure, got %v", results[1])
	}
	w.Restart(1)
	if c.Fault != "crash-before" && c.Resolution != "same" {
		next := map[app.ConflictCandidate]bool{{Value: "left-resolution"}: true, {Value: rightChoice.Value, Deleted: rightChoice.Delete}: true}
		for _, i := range []int{0, 1} {
			if err := w.compoundCandidates(ctx, i, next); err != nil {
				return err
			}
		}
		set, err = a.ListConflicts(ctx, "default")
		if err != nil {
			return err
		}
		if err := a.ResolveSecrets(ctx, "default", set.Heads, []app.SecretChoice{{Key: "K", Value: "final-resolution"}}); err != nil {
			return err
		}
		w.Model["default"]["K"] = "final-resolution"
	} else {
		w.Model["default"]["K"] = "left-resolution"
	}
	// The observer missed both forks and both resolutions. Compact before it
	// reconnects so recovery must also process the signed history floor.
	if c.Fault != "crash-before" && c.Resolution == "same" {
		_, err := a.CompactHistory(ctx, "default", 1)
		if err := requireCode(err, apperr.CodeConflict); err != nil {
			return err
		}
	}
	if err := a.SyncSecrets(ctx, "default"); err != nil {
		return err
	}
	if _, err := a.CompactHistory(ctx, "default", 1); err != nil {
		return err
	}
	w.Devices[3].Store.Arm(Fault{})
	w.Restart(3)
	if c.Control == "remove-writer" {
		if _, err := w.Devices[2].App.InitializeRepository(ctx, app.InitOptions{}); err != nil {
			return err
		}
		if err := a.ApproveMember(ctx, w.Devices[2].ID); err != nil {
			return err
		}
	}
	if err := w.Check(ctx, "default"); err != nil {
		return err
	}
	if err := w.Check(ctx, "production"); err != nil {
		return err
	}
	if err := w.Devices[3].App.AddSecret(ctx, "default", "RETURNED", "after-compaction"); err != nil {
		return err
	}
	w.Model["default"]["RETURNED"] = "after-compaction"
	return w.Check(ctx, "default")
}

func (w *World) compoundCandidates(ctx context.Context, device int, want map[app.ConflictCandidate]bool) error {
	a := w.Devices[device].App
	if _, err := a.ListSecrets(ctx, "default"); requireCode(err, apperr.CodeSecretConflict) != nil {
		return fmt.Errorf("compound device %d read unresolved conflict: %v", device, err)
	}
	set, err := a.ListConflicts(ctx, "default")
	if err != nil {
		return err
	}
	if len(set.Conflicts) != 1 || set.Conflicts[0].Key != "K" {
		return fmt.Errorf("compound unexpected conflict set: %+v", set)
	}
	got := map[app.ConflictCandidate]bool{}
	for _, candidate := range set.Conflicts[0].Candidates {
		got[candidate] = true
	}
	if !reflect.DeepEqual(got, want) {
		return fmt.Errorf("compound candidates device %d got %v want %v", device, got, want)
	}
	return nil
}
