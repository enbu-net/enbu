package simulation

import (
	"context"
	"fmt"
	"path/filepath"
	"reflect"

	"github.com/enbu-net/enbu/pkg/apperr"
	"github.com/enbu-net/enbu/pkg/config"
	"github.com/enbu-net/enbu/pkg/wsp"
)

// MultipleWorkspaces gives each person two repositories and storage locations,
// sharing their durable identity namespace, cache, checkpoints and personal state.
func (w *World) MultipleWorkspaces(ctx context.Context) error {
	ctx = wsp.WithSerialHeadReads(ctx)
	other, err := NewWorld(filepath.Join(w.Root, "second-workspace"), w.Tape, len(w.Devices))
	if err != nil {
		return err
	}
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
		d.Store.advance = person.Store.advance
	}
	for i := range other.Devices {
		bindPerson(i)
	}
	if err := other.Bootstrap(ctx); err != nil {
		return err
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
