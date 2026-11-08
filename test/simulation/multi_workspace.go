package simulation

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"

	"github.com/enbu-net/enbu/pkg/apperr"
	"github.com/enbu-net/enbu/pkg/config"
	"github.com/enbu-net/enbu/pkg/storage"
	"github.com/enbu-net/enbu/pkg/storage/storagetest"
	"github.com/enbu-net/enbu/pkg/wsp"
	"github.com/opencontainers/go-digest"
)

// MultipleWorkspaces gives each person two repositories,
// sharing their durable identity namespace, cache, checkpoints and personal state.
func (w *World) MultipleWorkspaces(ctx context.Context, sharedStorage bool) error {
	ctx = wsp.WithSerialHeadReads(ctx)
	other, err := NewWorld(filepath.Join(w.Root, "second-workspace"), w.Tape, len(w.Devices))
	if err != nil {
		return err
	}
	joinedStorage := false
	other.Clock = w.Clock
	other.timeline = w.timeline
	// IDs and physical time belong to the simulation, not the workspace. Resetting
	// a second world's ID counter would accidentally reuse the first workspace ID.
	bindPerson := func(i int) {
		d, person := other.Devices[i], w.Devices[i]
		d.Keys.workspaces = person.Keys.workspaces
		d.App.Identities = d.Keys
		d.App.CheckpointDir = person.App.CheckpointDir
		d.App.CacheDir = person.App.CacheDir
		d.App.Runtime.LocalStateDir = person.App.Runtime.LocalStateDir
		d.App.Runtime.Clock = person.App.Runtime.Clock
		d.App.Runtime.NewID = person.App.Runtime.NewID
		d.App.StorageURL = "oci://simulation.invalid/second-workspace"
		if joinedStorage {
			d.Store.Store = person.Store.Store
			d.App.StorageURL = person.App.StorageURL
		}
		d.Store.advance = person.Store.advance
	}
	for i := range other.Devices {
		bindPerson(i)
	}
	if sharedStorage {
		// A storage location is founded once. A second init must not overwrite
		// it or adopt a root supplied by the untrusted backend.
		collision, err := NewWorld(filepath.Join(w.Root, "occupied-storage"), w.Tape, 1)
		if err != nil {
			return err
		}
		d := collision.Devices[0]
		d.Store.Store = w.Devices[0].Store.Store
		d.Store.advance = w.Devices[0].Store.advance
		d.App.Runtime.Clock = w.Devices[0].App.Runtime.Clock
		d.App.Runtime.NewID = w.Devices[0].App.Runtime.NewID
		if _, err := d.App.InitializeRepository(ctx); requireCode(err, apperr.CodeIncompatibleStorage) != nil {
			return fmt.Errorf("second workspace founded in occupied storage: %v", err)
		}
		if err := w.Check(ctx, "default"); err != nil {
			return err
		}
	}
	if err := other.Bootstrap(ctx); err != nil {
		return err
	}
	if sharedStorage {
		// Simulate a backend/attacker mixing independently founded locations.
		// Bootstrap has no state blobs yet; copy both unscoped namespaces before
		// all subsequent real operations share one object store.
		for _, kind := range []storage.Kind{storage.KindControl, storage.KindRequest} {
			revs, err := other.Devices[0].Store.Discover(ctx, kind, "")
			if err != nil {
				return err
			}
			for _, rev := range revs {
				head, err := other.Devices[0].Store.FetchHead(ctx, kind, "", rev)
				if err != nil {
					return err
				}
				if err := w.Devices[0].Store.Publish(ctx, storage.Object{Kind: kind, Rev: rev, Head: head}); err != nil {
					return err
				}
			}
		}
		joinedStorage = true
		for i := range other.Devices {
			bindPerson(i)
		}
	}
	firstConfig, err := config.LoadProjectFrom(w.Devices[0].App.RepositoryDir)
	if err != nil {
		return err
	}
	secondConfig, err := config.LoadProjectFrom(other.Devices[0].App.RepositoryDir)
	if err != nil {
		return err
	}
	if firstConfig.WorkspaceID == secondConfig.WorkspaceID || firstConfig.ControlGenesis == secondConfig.ControlGenesis {
		return fmt.Errorf("workspace fixture reused identity or trust root")
	}
	for i := range w.Devices {
		if w.Devices[i].ID == other.Devices[i].ID {
			return fmt.Errorf("person %d reused a workspace signing key", i)
		}
	}
	for index, world := range []*World{w, other} {
		value := fmt.Sprintf("workspace-%d", index)
		if _, err := world.Devices[0].App.ImportSecrets(ctx, "default", map[string]string{"BASE": value, "TOKEN": value}, true); err != nil {
			return err
		}
		world.Model["default"] = map[string]string{"BASE": value, "TOKEN": value}
		env := []string{"alpha", "beta"}[index]
		if err := world.Devices[0].App.CreateEnvironment(env); err != nil {
			return err
		}
		if err := world.Devices[0].App.AddSecret(ctx, env, "TOKEN", value+"-environment"); err != nil {
			return err
		}
		world.Model[env] = map[string]string{"TOKEN": value + "-environment"}
		if err := world.Share(0); err != nil {
			return err
		}
	}
	if current, err := w.Devices[0].App.CurrentEnvironment(); err != nil || current != "alpha" {
		return fmt.Errorf("first workspace selection changed: %s %v", current, err)
	}
	if current, err := other.Devices[0].App.CurrentEnvironment(); err != nil || current != "beta" {
		return fmt.Errorf("second workspace selection changed: %s %v", current, err)
	}
	checkBoth := func() error {
		for index, world := range []*World{w, other} {
			for _, env := range []string{"default", []string{"alpha", "beta"}[index]} {
				if err := world.Check(ctx, env); err != nil {
					return err
				}
			}
		}
		return nil
	}
	if err := checkBoth(); err != nil {
		return err
	}
	// Two applications owned by the same person publish the same variable name
	// simultaneously to different workspaces while sharing their local stores.
	teammate := w.Devices[1]
	w.Devices[1] = other.Devices[0]
	err = func() error {
		defer func() { w.Devices[1] = teammate }()
		return w.Batch(ctx, "publish", []func(int) error{
			func(int) error { return w.Devices[0].App.AddSecret(ctx, "default", "SIMULTANEOUS", "first") },
			func(int) error { return other.Devices[0].App.AddSecret(ctx, "default", "SIMULTANEOUS", "second") },
		})
	}()
	if err != nil {
		return err
	}
	w.Model["default"]["SIMULTANEOUS"] = "first"
	other.Model["default"]["SIMULTANEOUS"] = "second"
	if err := checkBoth(); err != nil {
		return err
	}
	// Each person's two applications share local security directories, but not
	// operation cancellation. Interrupt either writer at a known durable boundary
	// while its other workspace acknowledges a real team update.
	for direction, pair := range [][2]*World{{w, other}, {other, w}} {
		writer, neighbor := pair[0], pair[1]
		for _, committed := range []bool{false, true} {
			key := fmt.Sprintf("CANCEL_%d_%t", direction, committed)
			callCtx, cancel := context.WithCancel(ctx)
			store := writer.Devices[0].Store
			base := store.Store
			fired := false
			var neighborErr error
			store.Store = storagetest.Wrap(base, storagetest.Hooks{Publish: func(c context.Context, next storage.Store, object storage.Object) error {
				if object.Kind != storage.KindState || fired {
					return next.Publish(c, object)
				}
				fired = true
				if committed {
					if err := next.Publish(c, object); err != nil {
						return err
					}
				}
				cancel()
				neighborErr = neighbor.Devices[0].App.AddSecret(ctx, "default", key, "neighbor-acknowledged")
				return c.Err()
			}})
			err := writer.Devices[0].App.AddSecret(callCtx, "default", key, "writer-uncertain")
			store.Store = base
			cancel()
			if !fired || !errors.Is(err, context.Canceled) || neighborErr != nil {
				return fmt.Errorf("cross-workspace cancellation: fired=%t writer=%v neighbor=%v", fired, err, neighborErr)
			}
			neighbor.Model["default"][key] = "neighbor-acknowledged"
			if committed {
				writer.Model["default"][key] = "writer-uncertain"
			}
			if err := checkBoth(); err != nil {
				return err
			}
			// Cold-cache recovery must agree with the warm-cache observers while
			// retaining trust pins, checkpoints and per-workspace key slots.
			if err := os.RemoveAll(writer.Devices[0].App.CacheDir); err != nil {
				return err
			}
			w.Restart(0)
			other.Restart(0)
			bindPerson(0)
			if err := checkBoth(); err != nil {
				return err
			}
			if !committed {
				if err := writer.Devices[0].App.AddSecret(ctx, "default", key, "writer-retried"); err != nil {
					return err
				}
				writer.Model["default"][key] = "writer-retried"
			}
			if err := checkBoth(); err != nil {
				return err
			}
		}
	}
	// Relocate genuine signed ciphertext into the other workspace's scope in
	// both directions. A valid signature from a foreign principal is insufficient.
	for _, pair := range [][2]*World{{w, other}, {other, w}} {
		source, target := pair[0], pair[1]
		src, err := config.LoadProjectFrom(source.Devices[0].App.RepositoryDir)
		if err != nil {
			return err
		}
		dst, err := config.LoadProjectFrom(target.Devices[0].App.RepositoryDir)
		if err != nil {
			return err
		}
		view, err := wsp.LoadControl(ctx, source.Devices[0].Store, src.WorkspaceID, digest.Digest(src.ControlGenesis), nil)
		if err != nil {
			return err
		}
		states, err := wsp.LoadStates(ctx, source.Devices[0].Store, view, src.WorkspaceID, src.Resource("default"))
		if err != nil {
			return err
		}
		if len(states.Heads) == 0 {
			return fmt.Errorf("foreign replay fixture has no source heads")
		}
		for _, head := range states.Heads {
			body, err := source.Devices[0].Store.FetchHead(ctx, storage.KindState, storage.StateScope(src.WorkspaceID, src.Resource("default")), head.Digest)
			if err != nil {
				return err
			}
			cipher, err := wsp.ReadCiphertext(ctx, source.Devices[0].Store, head)
			if err != nil {
				return err
			}
			if err := target.Devices[0].Store.Publish(ctx, storage.Object{Kind: storage.KindState, Scope: storage.StateScope(dst.WorkspaceID, dst.Resource("default")), Rev: head.Digest, Head: body, Blobs: [][]byte{cipher}}); err != nil {
				return err
			}
		}
	}
	if err := checkBoth(); err != nil {
		return err
	}
	// Compaction may reclaim the replayed junk but must not delete even one
	// revision from the neighboring workspace, including its historical states.
	neighborScope := storage.StateScope(secondConfig.WorkspaceID, secondConfig.Resource("default"))
	beforeRevs, err := other.Devices[0].Store.Discover(ctx, storage.KindState, neighborScope)
	if err != nil {
		return err
	}
	if _, err := w.Devices[0].App.CompactHistory(ctx, "default", 1); err != nil {
		return err
	}
	afterRevs, err := other.Devices[0].Store.Discover(ctx, storage.KindState, neighborScope)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(beforeRevs, afterRevs) {
		return fmt.Errorf("compaction deleted neighboring workspace revisions")
	}
	if err := checkBoth(); err != nil {
		return err
	}
	// Removing a person from one project must not remove them from another.
	if err := w.Devices[0].App.RemoveMember(ctx, w.Devices[1].ID); err != nil {
		return err
	}
	if _, err := w.Devices[1].App.ListSecrets(ctx, "default"); requireCode(err, apperr.CodeNotMember) != nil {
		return fmt.Errorf("first workspace removal failed: %v", err)
	}
	if err := other.Check(ctx, "default"); err != nil {
		return err
	}
	if _, err := w.Devices[1].App.InitializeRepository(ctx); err != nil {
		return err
	}
	requests, err := other.Devices[0].App.ListJoinRequests(ctx)
	if err != nil {
		return err
	}
	for _, request := range requests {
		if request.DeviceID == w.Devices[1].ID {
			return fmt.Errorf("join request crossed workspace boundary")
		}
	}
	if err := requireCode(other.Devices[0].App.ApproveMember(ctx, w.Devices[1].ID), apperr.CodeInvalidArgument); err != nil {
		return fmt.Errorf("foreign request approved: %w", err)
	}
	if err := w.Devices[0].App.ApproveMember(ctx, w.Devices[1].ID); err != nil {
		return err
	}
	// A pending/approved key upgrade has no authority to modify the other key.
	before, err := other.Devices[1].Keys.Info(secondConfig.WorkspaceID)
	if err != nil {
		return err
	}
	if _, err := w.Devices[1].App.UpgradeIdentity(ctx); err != nil {
		return err
	}
	if err := w.Devices[0].App.ApproveMember(ctx, w.Devices[1].ID); err != nil {
		return err
	}
	if err := checkBoth(); err != nil {
		return err
	}
	after, err := other.Devices[1].Keys.Info(secondConfig.WorkspaceID)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(before, after) {
		return fmt.Errorf("key upgrade crossed workspace boundary")
	}
	for i := range w.Devices {
		w.Restart(i)
		other.Restart(i)
		bindPerson(i)
	}
	if err := checkBoth(); err != nil {
		return err
	}
	firstConfig, err = config.LoadProjectFrom(w.Devices[0].App.RepositoryDir)
	if err != nil {
		return err
	}
	secondConfig, err = config.LoadProjectFrom(other.Devices[0].App.RepositoryDir)
	if err != nil {
		return err
	}
	// Replaying the other project's config into an already pinned checkout must
	// fail closed; sharing a key-store directory is not permission to cross roots.
	if err := config.SaveProjectTo(w.Devices[0].App.RepositoryDir, secondConfig); err != nil {
		return err
	}
	if _, err := w.Devices[0].App.ListSecrets(ctx, "default"); requireCode(err, apperr.CodeTrustRootChanged) != nil {
		return fmt.Errorf("foreign workspace config accepted: %v", err)
	}
	if err := config.SaveProjectTo(w.Devices[0].App.RepositoryDir, firstConfig); err != nil {
		return err
	}
	if err := checkBoth(); err != nil {
		return err
	}
	return w.Tape.Observe("second-workspace-model", secondConfig.WorkspaceID, other.Model)
}
