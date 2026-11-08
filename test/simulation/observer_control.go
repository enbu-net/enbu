package simulation

import (
	"context"
	"fmt"
	"maps"
	"os"
	"reflect"
	"slices"

	"github.com/enbu-net/enbu/pkg/apperr"
	"github.com/enbu-net/enbu/pkg/storage"
	"github.com/opencontainers/go-digest"
)

// Role-only changes isolate Control equivocation: each writer sees a valid
// linear member history, while the complete view contains two competing tips.
func (w *World) ObserverControlEquivocation(ctx context.Context, cold bool) error {
	if len(w.Devices) < 4 {
		return fmt.Errorf("control equivocation needs four devices")
	}
	if err := w.Devices[0].App.SetAdmin(ctx, w.Devices[1].ID, true); err != nil {
		return err
	}
	if err := w.Check(ctx, "default"); err != nil {
		return err
	}
	seen, err := w.Devices[0].App.ListConflicts(ctx, "default")
	if err != nil {
		return err
	}
	baseRoles := map[string]bool{}
	backends := make([]storage.Store, len(w.Devices))
	for i, d := range w.Devices {
		baseRoles[d.ID] = i < 2
		backends[i] = d.Store.Store
	}
	setView := func(i int, hidden ...digest.Digest) error {
		if err := w.Tape.Observe("observer-hidden-controls", i, hidden); err != nil {
			return err
		}
		if len(hidden) == 0 {
			w.Devices[i].Store.Store = backends[i]
		} else {
			w.Devices[i].Store.Store = hideObserverRevisions(backends[i], storage.KindControl, "", slices.Clone(hidden))
		}
		return nil
	}
	refs, err := w.Devices[2].Store.Discover(ctx, storage.KindControl, "")
	if err != nil {
		return err
	}
	nextControl := func() (digest.Digest, error) {
		latest, err := w.Devices[2].Store.Discover(ctx, storage.KindControl, "")
		if err != nil {
			return "", err
		}
		var added []digest.Digest
		for _, rev := range latest {
			if !slices.Contains(refs, rev) {
				added = append(added, rev)
			}
		}
		if len(added) != 1 {
			return "", fmt.Errorf("expected one Control publication, got %d", len(added))
		}
		refs = latest
		return added[0], nil
	}
	checkRoles := func(i int, want map[string]bool) error {
		start := len(w.Tape.Recording.Entries)
		members, err := w.Devices[i].App.ListMembers(ctx)
		if err != nil {
			return err
		}
		actual := map[string]bool{}
		for _, member := range members {
			actual[member.DeviceID] = member.Admin
		}
		if len(members) != len(want) || !reflect.DeepEqual(actual, want) {
			return fmt.Errorf("reader %d accepted unexpected principals or roles: got %v want %v", i, actual, want)
		}
		return requireMetadataOnlyStorage(w.Tape.Recording.Entries[start:])
	}
	if err := w.Devices[0].App.SetAdmin(ctx, w.Devices[2].ID, true); err != nil {
		return err
	}
	left, err := nextControl()
	if err != nil {
		return err
	}
	if err := setView(1, left); err != nil {
		return err
	}
	if err := w.Devices[1].App.SetAdmin(ctx, w.Devices[3].ID, true); err != nil {
		return err
	}
	right, err := nextControl()
	if err != nil {
		return err
	}
	if err := setView(0, right); err != nil {
		return err
	}
	for i, d := range w.Devices {
		if cold {
			if err := os.RemoveAll(d.App.CacheDir); err != nil {
				return err
			}
		}
		w.Restart(i)
	}
	leftRoles, rightRoles := maps.Clone(baseRoles), maps.Clone(baseRoles)
	leftRoles[w.Devices[2].ID] = true
	rightRoles[w.Devices[3].ID] = true
	if err := checkRoles(0, leftRoles); err != nil {
		return err
	}
	if err := checkRoles(1, rightRoles); err != nil {
		return err
	}
	reject := func(i int, code apperr.Code) error {
		if cold {
			if err := os.RemoveAll(w.Devices[i].App.CacheDir); err != nil {
				return err
			}
			w.Restart(i)
		}
		a := w.Devices[i].App
		start := len(w.Tape.Recording.Entries)
		members, err := a.ListMembers(ctx)
		if e := requireCode(err, code); e != nil || members != nil {
			return fmt.Errorf("reader %d exposed a rejected member view: %v", i, err)
		}
		secrets, err := a.ListSecrets(ctx, "default")
		if e := requireCode(err, code); e != nil || secrets != nil {
			return fmt.Errorf("reader %d exposed secrets under a rejected Control: %v", i, err)
		}
		for _, operation := range []struct {
			name string
			run  func() error
		}{
			{"add", func() error { return a.AddSecret(ctx, "default", "MUST_NOT_WRITE", "control-equivocation-canary") }},
			{"edit", func() error { return a.EditSecret(ctx, "default", "BASE", "control-equivocation-canary") }},
			{"delete", func() error { return a.DeleteSecret(ctx, "default", "BASE") }},
			{"sync", func() error { return a.SyncSecrets(ctx, "default") }},
			{"resolve secrets", func() error { return a.ResolveSecrets(ctx, "default", slices.Clone(seen.Heads), nil) }},
			{"restore history", func() error { return a.RestoreHistory(ctx, "default", 1) }},
			{"promote", func() error { return a.SetAdmin(ctx, w.Devices[2].ID, true) }},
			{"demote", func() error { return a.SetAdmin(ctx, w.Devices[1].ID, false) }},
			{"remove", func() error { return a.RemoveMember(ctx, w.Devices[2].ID) }},
			{"approve", func() error { return a.ApproveMember(ctx, w.Devices[2].ID) }},
			{"import", func() error {
				result, err := a.ImportSecrets(ctx, "default", map[string]string{"BASE": "control-equivocation-canary"}, true)
				if result != nil {
					return fmt.Errorf("rejected import returned a result")
				}
				return err
			}},
			{"compact", func() error {
				result, err := a.CompactHistory(ctx, "default", 1)
				if result != nil {
					return fmt.Errorf("rejected compaction returned a result")
				}
				return err
			}},
			{"list requests", func() error {
				result, err := a.ListJoinRequests(ctx)
				if result != nil {
					return fmt.Errorf("rejected request listing returned data")
				}
				return err
			}},
			{"list conflicts", func() error {
				result, err := a.ListConflicts(ctx, "default")
				if result != nil {
					return fmt.Errorf("rejected conflict listing returned data")
				}
				return err
			}},
			{"list history", func() error {
				result, err := a.ListHistory(ctx, "default")
				if result != nil {
					return fmt.Errorf("rejected history listing returned data")
				}
				return err
			}},
			{"diff history", func() error {
				result, err := a.DiffHistory(ctx, "default", 1, 1)
				if result != nil {
					return fmt.Errorf("rejected history diff returned data")
				}
				return err
			}},
			{"pull data", func() error {
				result, err := a.PullSecretsData(ctx, "default")
				if result != nil {
					return fmt.Errorf("rejected pull returned data")
				}
				return err
			}},
		} {
			if err := requireCode(operation.run(), code); err != nil {
				return fmt.Errorf("reader %d %s: %w", i, operation.name, err)
			}
		}
		return requireMetadataOnlyStorage(w.Tape.Recording.Entries[start:])
	}
	for i := 2; i < len(w.Devices); i++ {
		if err := reject(i, apperr.CodeControlForked); err != nil {
			return err
		}
	}
	for i, hidden := range []digest.Digest{left, right} {
		if err := setView(i, hidden); err != nil {
			return err
		}
		if err := reject(i, apperr.CodeRollback); err != nil {
			return err
		}
	}
	for i := range w.Devices {
		if err := setView(i); err != nil {
			return err
		}
	}
	// Neither unilateral promotion authorizes joining the complete fork.
	for i := 2; i < len(w.Devices); i++ {
		if err := reject(i, apperr.CodeControlForked); err != nil {
			return err
		}
	}
	// Device 0 is an admin of both heads, so its next operation joins them.
	if _, err := w.Devices[0].App.ListSecrets(ctx, "default"); err != nil {
		return err
	}
	resolution, err := nextControl()
	if err != nil {
		return err
	}
	for i := range w.Devices {
		if err := checkRoles(i, baseRoles); err != nil {
			return err
		}
	}
	if err := w.Check(ctx, "default"); err != nil {
		return err
	}
	for i := range w.Devices {
		if err := setView(i, resolution); err != nil {
			return err
		}
		if err := reject(i, apperr.CodeRollback); err != nil {
			return err
		}
		if err := setView(i); err != nil {
			return err
		}
		w.Restart(i)
	}
	// After conservative resolution, an explicit new grant is allowed. This
	// produces the same role map as the earlier left branch, with new ancestry.
	if err := w.Devices[1].App.SetAdmin(ctx, w.Devices[2].ID, true); err != nil {
		return err
	}
	grant, err := nextControl()
	if err != nil {
		return err
	}
	for i := range w.Devices {
		if err := checkRoles(i, leftRoles); err != nil {
			return err
		}
	}
	for i := range w.Devices {
		if err := setView(i, right, resolution, grant); err != nil {
			return err
		}
		if err := reject(i, apperr.CodeRollback); err != nil {
			return err
		}
		if err := setView(i); err != nil {
			return err
		}
		w.Restart(i)
	}
	for i, d := range w.Devices {
		if err := checkRoles(i, leftRoles); err != nil {
			return err
		}
		key := fmt.Sprintf("AFTER_CONTROL_VIEW_%d", i)
		if err := d.App.AddSecret(ctx, "default", key, "acknowledged"); err != nil {
			return err
		}
		w.Model["default"][key] = "acknowledged"
	}
	return w.Check(ctx, "default")
}
