package simulation

import (
	"context"
	"errors"
	"fmt"
	"reflect"

	"github.com/enbu-net/enbu/app"
	"github.com/enbu-net/enbu/pkg/apperr"
	"github.com/enbu-net/enbu/pkg/wsp"
)

// Swarm uses application operations, rather than constructed revisions, to
// force every writer past its initial read before any writer can publish.
func (w *World) Swarm(ctx context.Context, scene string) error {
	ctx = wsp.WithSerialHeadReads(ctx)
	base := map[string]string{"K": "original", "L": "original", "UNRELATED": "kept"}
	for i := range w.Devices {
		base[fmt.Sprintf("OWN_%d", i)] = "original"
	}
	if _, err := w.Devices[0].App.ImportSecrets(ctx, "default", base, true); err != nil {
		return err
	}
	w.Model["default"] = clone(base)
	if err := w.Check(ctx, "default"); err != nil {
		return err
	}
	writers := len(w.Devices)
	if scene == "offline-observer" {
		writers--
		d := w.Devices[writers]
		d.Store.Arm(Fault{Method: "*", Mode: "partition"})
		if _, err := d.App.ListSecrets(ctx, "default"); !errors.Is(err, ErrOffline) {
			return fmt.Errorf("partitioned observer: expected offline error, got %v", err)
		}
	}
	want := clone(base)
	candidates := map[string]map[app.ConflictCandidate]bool{}
	ops := make([]func(int) error, writers)
	for i := range writers {
		key, value := fmt.Sprintf("OWN_%d", i), fmt.Sprintf("writer-%d", i)
		kind := "edit"
		switch scene {
		case "disjoint-add", "offline-observer":
			kind, key = "add", fmt.Sprintf("NEW_%d", i)
		case "disjoint-mixed":
			kind = []string{"edit", "delete", "import", "sync"}[i%4]
		case "identical-edit":
			key, value = "K", "same"
		case "identical-delete":
			kind, key = "delete", "K"
		case "distinct-edit", "edit-delete", "conflicting-import":
			key = "K"
			if scene == "edit-delete" && i%2 == 0 {
				kind = "delete"
			}
			if scene == "conflicting-import" {
				kind = "import"
			}
			candidate := app.ConflictCandidate{Value: value}
			if kind == "delete" {
				candidate = app.ConflictCandidate{Deleted: true}
			}
			if candidates[key] == nil {
				candidates[key] = map[app.ConflictCandidate]bool{}
			}
			candidates[key][candidate] = true
			if scene == "conflicting-import" {
				if candidates["L"] == nil {
					candidates["L"] = map[app.ConflictCandidate]bool{}
				}
				candidates["L"][app.ConflictCandidate{Value: "second-" + value}] = true
			}
		default:
			return fmt.Errorf("unknown swarm scene %q", scene)
		}
		switch kind {
		case "add", "edit", "import":
			want[key] = value
		case "delete":
			delete(want, key)
		}
		ops[i] = func(actor int) error {
			a := w.Devices[actor].App
			switch kind {
			case "add":
				return a.AddSecret(ctx, "default", key, value)
			case "edit":
				return a.EditSecret(ctx, "default", key, value)
			case "delete":
				return a.DeleteSecret(ctx, "default", key)
			case "import":
				values := map[string]string{key: value}
				if scene == "conflicting-import" {
					values["L"] = "second-" + value
				}
				_, err := a.ImportSecrets(ctx, "default", values, true)
				return err
			default:
				return a.SyncSecrets(ctx, "default")
			}
		}
	}
	results, err := w.runBatch(ctx, "publish", ops)
	if err != nil {
		return err
	}
	for i, result := range results {
		if result != nil && (len(candidates) == 0 || ErrorCode(result) != string(apperr.CodeSecretConflict)) {
			return fmt.Errorf("swarm %s actor %d: %w", scene, i, result)
		}
	}
	if scene == "offline-observer" {
		w.Devices[writers].Store.Arm(Fault{})
		w.Restart(writers)
	}
	if len(candidates) > 0 {
		for i, d := range w.Devices {
			if _, err := d.App.ListSecrets(ctx, "default"); requireCode(err, apperr.CodeSecretConflict) != nil {
				return fmt.Errorf("swarm conflict readable on device %d: %v", i, err)
			}
			set, err := d.App.ListConflicts(ctx, "default")
			if err != nil {
				return err
			}
			got := map[string]map[app.ConflictCandidate]bool{}
			for _, conflict := range set.Conflicts {
				got[conflict.Key] = map[app.ConflictCandidate]bool{}
				for _, candidate := range conflict.Candidates {
					got[conflict.Key][candidate] = true
				}
			}
			if !reflect.DeepEqual(got, candidates) {
				return fmt.Errorf("swarm lost candidates device %d: got %v want %v", i, got, candidates)
			}
		}
		set, err := w.Devices[0].App.ListConflicts(ctx, "default")
		if err != nil {
			return err
		}
		choices := []app.SecretChoice{{Key: "K", Value: "resolved"}}
		want["K"] = "resolved"
		if scene == "conflicting-import" {
			choices = append(choices, app.SecretChoice{Key: "L", Delete: true})
			delete(want, "L")
		}
		if err := w.Devices[0].App.ResolveSecrets(ctx, "default", set.Heads, choices); err != nil {
			return err
		}
	}
	w.Model["default"] = want
	if err := w.Check(ctx, "default"); err != nil {
		return err
	}
	// Every device, including the returning observer, writes again after restart.
	// This catches a resolution that looks correct but leaves unusable checkpoints.
	ops = make([]func(int) error, len(w.Devices))
	for i := range w.Devices {
		w.Restart(i)
		key := fmt.Sprintf("AFTER_%d", i)
		want[key] = "acknowledged"
		ops[i] = func(actor int) error {
			return w.Devices[actor].App.AddSecret(ctx, "default", key, "acknowledged")
		}
	}
	if err := w.Batch(ctx, "publish", ops); err != nil {
		return err
	}
	for i := len(w.Devices) - 1; i >= 0; i-- {
		if err := w.Devices[i].App.SyncSecrets(ctx, "default"); err != nil {
			return err
		}
	}
	return w.Check(ctx, "default")
}
