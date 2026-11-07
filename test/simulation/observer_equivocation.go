package simulation

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"os"
	"reflect"
	"slices"

	"github.com/enbu-net/enbu/app"
	"github.com/enbu-net/enbu/pkg/apperr"
	"github.com/enbu-net/enbu/pkg/config"
	"github.com/enbu-net/enbu/pkg/storage"
	"github.com/enbu-net/enbu/pkg/storage/storagetest"
	"github.com/opencontainers/go-digest"
)

// Rollback checks precede ciphertext access. A later checkpoint recheck can
// still reject the operation after decryption, so checking its error alone is
// insufficient to enforce this ordering.
func requireMetadataOnlyStorage(entries []Entry) error {
	if err := requireReadOnlyStorage(entries); err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.Kind != "storage-request" {
			continue
		}
		var request struct{ Method string }
		if err := json.Unmarshal(entry.Output, &request); err != nil {
			return err
		}
		if request.Method == "blob" {
			return fmt.Errorf("rollback probe fetched ciphertext before rejecting the view")
		}
	}
	return nil
}

// hideObserverRevisions changes only one reader's network view. Hidden immutable
// objects remain in shared storage, but are absent from listing and direct
// header/blob fetches for that reader. The captured policy is immutable.
func hideObserverRevisions(base storage.Store, kind storage.Kind, scope string, hidden []digest.Digest) storage.Store {
	hides := func(k storage.Kind, resource string, rev digest.Digest) bool {
		return k == kind && resource == scope && slices.Contains(hidden, rev)
	}
	return storagetest.Wrap(base, storagetest.Hooks{
		Discover: func(ctx context.Context, next storage.Store, k storage.Kind, resource string) ([]digest.Digest, error) {
			refs, err := next.Discover(ctx, k, resource)
			if err != nil {
				return nil, err
			}
			var out []digest.Digest
			for _, rev := range refs {
				if !hides(k, resource, rev) {
					out = append(out, rev)
				}
			}
			return out, nil
		},
		FetchHead: func(ctx context.Context, next storage.Store, k storage.Kind, resource string, rev digest.Digest) ([]byte, error) {
			if hides(k, resource, rev) {
				return nil, storage.ErrNotFound
			}
			return next.FetchHead(ctx, k, resource, rev)
		},
		OpenBlob: func(ctx context.Context, next storage.Store, k storage.Kind, resource string, rev digest.Digest, index int) (io.ReadCloser, error) {
			if hides(k, resource, rev) {
				return nil, storage.ErrNotFound
			}
			return next.OpenBlob(ctx, k, resource, rev, index)
		},
	})
}

func (w *World) ObserverStateEquivocation(ctx context.Context, conflict, cold bool) error {
	if len(w.Devices) < 3 {
		return fmt.Errorf("observer equivocation requires at least three devices")
	}
	if err := w.Check(ctx, "default"); err != nil {
		return err
	}
	cfg, err := config.LoadProjectFrom(w.Devices[0].App.RepositoryDir)
	if err != nil {
		return err
	}
	scope := storage.StateScope(cfg.WorkspaceID, cfg.Resource("default"))
	backends := make([]storage.Store, len(w.Devices))
	for i, d := range w.Devices {
		backends[i] = d.Store.Store
	}
	setView := func(i int, hidden ...digest.Digest) error {
		if err := w.Tape.Observe("observer-hidden-states", []any{i, scope}, hidden); err != nil {
			return err
		}
		if len(hidden) == 0 {
			w.Devices[i].Store.Store = backends[i]
		} else {
			w.Devices[i].Store.Store = hideObserverRevisions(backends[i], storage.KindState, scope, slices.Clone(hidden))
		}
		return nil
	}
	refs, err := w.Devices[2].Store.Discover(ctx, storage.KindState, scope)
	if err != nil {
		return err
	}
	nextPublication := func() (digest.Digest, error) {
		latest, err := w.Devices[2].Store.Discover(ctx, storage.KindState, scope)
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
			return "", fmt.Errorf("expected exactly one branch publication, got %d", len(added))
		}
		refs = latest
		return added[0], nil
	}
	left, right := maps.Clone(w.Model["default"]), maps.Clone(w.Model["default"])
	if conflict {
		left["BASE"], right["BASE"] = "left", "right"
		err = w.Devices[0].App.EditSecret(ctx, "default", "BASE", "left")
	} else {
		left["LEFT"], right["RIGHT"] = "acknowledged-left", "acknowledged-right"
		err = w.Devices[0].App.AddSecret(ctx, "default", "LEFT", left["LEFT"])
	}
	if err != nil {
		return err
	}
	leftRef, err := nextPublication()
	if err != nil {
		return err
	}
	if err := setView(1, leftRef); err != nil {
		return err
	}
	if conflict {
		err = w.Devices[1].App.EditSecret(ctx, "default", "BASE", "right")
	} else {
		err = w.Devices[1].App.AddSecret(ctx, "default", "RIGHT", right["RIGHT"])
	}
	if err != nil {
		return err
	}
	rightRef, err := nextPublication()
	if err != nil {
		return err
	}
	if err := setView(0, rightRef); err != nil {
		return err
	}
	// A restart cannot reset a reader's accepted-head witness. Cache state is
	// independently varied; the network view belongs to the attacker, not App.
	for i, d := range w.Devices {
		if cold {
			if err := os.RemoveAll(d.App.CacheDir); err != nil {
				return err
			}
		}
		w.Restart(i)
	}
	for i, want := range []map[string]string{left, right} {
		start := len(w.Tape.Recording.Entries)
		got, err := w.Devices[i].App.ListSecrets(ctx, "default")
		if err != nil || !reflect.DeepEqual(got, want) {
			return fmt.Errorf("isolated reader %d lost its accepted branch: %v", i, err)
		}
		if err := requireReadOnlyStorage(w.Tape.Recording.Entries[start:]); err != nil {
			return err
		}
	}
	union := maps.Clone(left)
	if !conflict {
		union["RIGHT"] = right["RIGHT"]
	}
	heads := []string{leftRef.Encoded(), rightRef.Encoded()}
	slices.Sort(heads)
	checkUnion := func(i int) error {
		start := len(w.Tape.Recording.Entries)
		got, err := w.Devices[i].App.ListSecrets(ctx, "default")
		if conflict {
			if e := requireCode(err, apperr.CodeSecretConflict); e != nil || got != nil {
				return fmt.Errorf("combined view failed to preserve conflict: %v", err)
			}
			set, err := w.Devices[i].App.ListConflicts(ctx, "default")
			if err != nil {
				return err
			}
			if !slices.Equal(set.Heads, heads) || len(set.Conflicts) != 1 || set.Conflicts[0].Key != "BASE" || len(set.Conflicts[0].Candidates) != 2 {
				return fmt.Errorf("combined view lost independently published heads or conflict keys")
			}
			candidates := map[app.ConflictCandidate]bool{}
			for _, candidate := range set.Conflicts[0].Candidates {
				candidates[candidate] = true
			}
			if !reflect.DeepEqual(candidates, map[app.ConflictCandidate]bool{{Value: "left"}: true, {Value: "right"}: true}) {
				return fmt.Errorf("combined view lost independent conflict candidates")
			}
		} else if err != nil || !reflect.DeepEqual(got, union) {
			return fmt.Errorf("combined view lost an acknowledged key: %v", err)
		}
		return requireReadOnlyStorage(w.Tape.Recording.Entries[start:])
	}
	for i := 2; i < len(w.Devices); i++ {
		if err := checkUnion(i); err != nil {
			return err
		}
	}
	rejectRollback := func(i int) error {
		if cold {
			if err := os.RemoveAll(w.Devices[i].App.CacheDir); err != nil {
				return err
			}
			w.Restart(i)
		}
		start := len(w.Tape.Recording.Entries)
		got, err := w.Devices[i].App.ListSecrets(ctx, "default")
		if e := requireCode(err, apperr.CodeRollback); e != nil || got != nil {
			return fmt.Errorf("reader %d accepted a view hiding its acknowledged head: %v", i, err)
		}
		if err := requireCode(w.Devices[i].App.AddSecret(ctx, "default", "MUST_NOT_WRITE", "equivocation-canary"), apperr.CodeRollback); err != nil {
			return err
		}
		if err := requireCode(w.Devices[i].App.SyncSecrets(ctx, "default"), apperr.CodeRollback); err != nil {
			return err
		}
		return requireMetadataOnlyStorage(w.Tape.Recording.Entries[start:])
	}
	for i := range w.Devices {
		hidden := leftRef
		if i == 1 {
			hidden = rightRef
		}
		if err := setView(i, hidden); err != nil {
			return err
		}
		if err := rejectRollback(i); err != nil {
			return err
		}
	}
	for i := range w.Devices {
		if err := setView(i); err != nil {
			return err
		}
	}
	for i := range w.Devices {
		if err := checkUnion(i); err != nil {
			return err
		}
	}
	if conflict {
		if err := w.Devices[0].App.ResolveSecrets(ctx, "default", heads, map[string]app.SecretChoice{"BASE": {Value: "resolved"}}); err != nil {
			return err
		}
		union["BASE"] = "resolved"
	} else if err := w.Devices[0].App.SyncSecrets(ctx, "default"); err != nil {
		return err
	}
	merged, err := nextPublication()
	if err != nil {
		return err
	}
	w.Model["default"] = union
	if err := w.Check(ctx, "default"); err != nil {
		return err
	}
	// The merged plaintext can equal a stale merged read. Signed ancestry and
	// the checkpoint, not plaintext equality, must still reject hiding its head.
	for i := range w.Devices {
		if err := setView(i, merged); err != nil {
			return err
		}
		if err := rejectRollback(i); err != nil {
			return err
		}
		if err := setView(i); err != nil {
			return err
		}
		w.Restart(i)
	}
	for i, d := range w.Devices {
		key := fmt.Sprintf("AFTER_VIEW_%d", i)
		if err := d.App.AddSecret(ctx, "default", key, "acknowledged"); err != nil {
			return err
		}
		w.Model["default"][key] = "acknowledged"
	}
	return w.Check(ctx, "default")
}
