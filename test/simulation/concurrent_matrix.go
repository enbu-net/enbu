package simulation

import (
	"context"
	"fmt"
	"reflect"

	"github.com/enbu-net/enbu/app"
	"github.com/enbu-net/enbu/pkg/apperr"
	"github.com/enbu-net/enbu/pkg/wsp"
)

type ConcurrentCase struct {
	Left, Right string
	SameKey     bool
}

var ConcurrentOperations = []string{"edit", "delete", "import", "sync"}

// ConcurrentCase forces both writers to the publication boundary. Different
// keys must compose; different changes to the same key must remain a conflict.
func (w *World) ConcurrentCase(ctx context.Context, c ConcurrentCase) error {
	ctx = wsp.WithSerialHeadReads(ctx)
	if c.Right == "compact" {
		if err := w.Devices[0].App.SetAdmin(ctx, w.Devices[1].ID, true); err != nil {
			return err
		}
	}
	base := map[string]string{"K0": "original", "K1": "original", "UNRELATED": "kept"}
	if c.Left == "add" && c.Right == "add" {
		delete(base, "K0")
		delete(base, "K1")
	}
	if c.Left == "restore" || c.Right == "restore" {
		historical := clone(base)
		historical["K0"] = "historical"
		if _, err := w.Devices[0].App.ImportSecrets(ctx, "default", historical, true); err != nil {
			return err
		}
	}
	if _, err := w.Devices[0].App.ImportSecrets(ctx, "default", base, true); err != nil {
		return err
	}
	w.Model["default"] = clone(base)
	kinds := []string{c.Left, c.Right}
	keys := []string{"K0", "K1"}
	if c.SameKey {
		keys[1] = "K0"
	}
	values := []string{"left", "right"}
	ops := make([]func(int) error, 2)
	for i, kind := range kinds {
		if kind == "restore" {
			keys[i], values[i] = "K0", "historical"
		}
		ops[i] = func(_ int) error {
			a := w.Devices[i].App
			switch kind {
			case "add":
				return a.AddSecret(ctx, "default", keys[i], values[i])
			case "edit":
				return a.EditSecret(ctx, "default", keys[i], values[i])
			case "delete":
				return a.DeleteSecret(ctx, "default", keys[i])
			case "import":
				_, err := a.ImportSecrets(ctx, "default", map[string]string{keys[i]: values[i]}, true)
				return err
			case "sync":
				return a.SyncSecrets(ctx, "default")
			case "restore":
				return a.RestoreHistory(ctx, "default", 1)
			case "compact":
				result, err := a.CompactHistory(ctx, "default", 1)
				if err == nil && result.Removed == 0 {
					return fmt.Errorf("concurrent compaction removed no historical revision")
				}
				return err
			default:
				return fmt.Errorf("unknown concurrent operation %s", kind)
			}
		}
	}
	conflict := c.SameKey && c.Left != "sync" && c.Right != "sync" && (c.Left != "delete" || c.Right != "delete") && (c.Left != "restore" || c.Right != "restore")
	results, err := w.runBatch(ctx, "publish", ops)
	if err != nil {
		return err
	}
	for _, result := range results {
		if result != nil && (!conflict || ErrorCode(result) != string(apperr.CodeSecretConflict)) {
			return fmt.Errorf("concurrent %+v: %w", c, result)
		}
	}
	if conflict {
		for _, d := range w.Devices {
			if _, err := d.App.ListSecrets(ctx, "default"); requireCode(err, apperr.CodeSecretConflict) != nil {
				return fmt.Errorf("conflicting %+v was readable: %v", c, err)
			}
		}
		set, err := w.Devices[0].App.ListConflicts(ctx, "default")
		if err != nil {
			return err
		}
		if len(set.Conflicts) != 1 || set.Conflicts[0].Key != "K0" {
			return fmt.Errorf("unexpected conflict set %+v", set)
		}
		wantCandidates := map[app.ConflictCandidate]bool{}
		for index, kind := range kinds {
			candidate := app.ConflictCandidate{Value: values[index]}
			if kind == "delete" {
				candidate = app.ConflictCandidate{Deleted: true}
			}
			wantCandidates[candidate] = true
		}
		gotCandidates := map[app.ConflictCandidate]bool{}
		for _, candidate := range set.Conflicts[0].Candidates {
			gotCandidates[candidate] = true
		}
		if !reflect.DeepEqual(gotCandidates, wantCandidates) {
			return fmt.Errorf("lost conflict candidate: got %v want %v", gotCandidates, wantCandidates)
		}
		if err := w.Devices[0].App.ResolveSecrets(ctx, "default", set.Heads, map[string]app.SecretChoice{"K0": {Value: "resolved"}}); err != nil {
			return err
		}
		w.Model["default"]["K0"] = "resolved"
	} else {
		for i, kind := range kinds {
			switch kind {
			case "add", "edit", "import", "restore":
				w.Model["default"][keys[i]] = values[i]
			case "delete":
				delete(w.Model["default"], keys[i])
			}
		}
	}
	if err := w.Tape.Observe("concurrent-case", c, conflict); err != nil {
		return err
	}
	return w.Check(ctx, "default")
}
