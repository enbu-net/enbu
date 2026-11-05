package simulation

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/enbu-net/enbu/pkg/config"
)

// LocalProcesses models two independent App processes owned by one person.
// Storage wrappers and process objects are distinct; durable keys, per-user
// selection, checkpoints, and caches are shared exactly as in CLI/GUI use.
func (w *World) LocalProcesses(ctx context.Context) error {
	if err := w.Devices[0].App.CreateEnvironment("process-selection"); err != nil {
		return err
	}
	if err := w.Devices[0].App.AddSecret(ctx, "process-selection", "SENTINEL", "kept"); err != nil {
		return err
	}
	w.Model["process-selection"] = map[string]string{"SENTINEL": "kept"}
	if err := w.Devices[0].App.SwitchEnvironment("default"); err != nil {
		return err
	}
	if err := w.Share(0); err != nil {
		return err
	}
	for _, otherCheckout := range []bool{false, true} {
		for _, c := range []ConcurrentCase{
			{Left: "edit", Right: "edit"},
			{Left: "edit", Right: "delete", SameKey: true},
			{Left: "restore", Right: "import", SameKey: true},
			{Left: "edit", Right: "compact"},
		} {
			if err := w.localProcessPair(ctx, otherCheckout, c); err != nil {
				return err
			}
		}
	}
	return w.Check(ctx, "process-selection")
}

func (w *World) localProcessPair(ctx context.Context, otherCheckout bool, c ConcurrentCase) error {
	primary := w.Devices[0]
	actualTeammate := w.Devices[1]
	keys := &Keys{Tape: w.Tape, Device: 0, workspaces: primary.Keys.workspaces}
	store := &Store{Store: primary.Store.Store, Tape: w.Tape, Device: 1, advance: primary.Store.advance}
	process := w.newApp(0, len(w.Devices), keys, store)
	if otherCheckout {
		process.RepositoryDir = filepath.Join(w.Root, "device-0-second-checkout")
		if err := os.MkdirAll(process.RepositoryDir, 0700); err != nil {
			return err
		}
		cfg, err := config.LoadProjectFrom(primary.App.RepositoryDir)
		if err != nil {
			return err
		}
		data, err := config.MarshalProject(cfg)
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(process.RepositoryDir, "enbu.toml"), data, 0600); err != nil {
			return err
		}
		path, err := config.ProjectConfigPathFrom(process.RepositoryDir)
		if err != nil || filepath.Dir(path) != process.RepositoryDir {
			return fmt.Errorf("second checkout reused another config: %s %v", path, err)
		}
	}
	if process == primary.App || process.Runtime == primary.App.Runtime || store == primary.Store || keys == primary.Keys {
		return fmt.Errorf("same-user fixture reused process objects")
	}
	if process.CheckpointDir != primary.App.CheckpointDir || process.CacheDir != primary.App.CacheDir || process.Runtime.LocalStateDir != primary.App.Runtime.LocalStateDir {
		return fmt.Errorf("same-user fixture failed to share durable state")
	}
	if current, err := process.CurrentEnvironment(); err != nil || current != "default" {
		return fmt.Errorf("process selection: %s %v", current, err)
	}
	// Workspace selection is personal, shared by this user's processes, and
	// independent of the real teammate's selection.
	if err := process.SwitchEnvironment("process-selection"); err != nil {
		return err
	}
	if current, err := primary.App.CurrentEnvironment(); err != nil || current != "process-selection" {
		return fmt.Errorf("same-person selection was not shared: %s %v", current, err)
	}
	if current, err := actualTeammate.App.CurrentEnvironment(); err != nil || current != "default" {
		return fmt.Errorf("selection leaked to teammate: %s %v", current, err)
	}
	if err := process.SwitchEnvironment("default"); err != nil {
		return err
	}
	// Keep the real second team member in storage, but use its actor slot for
	// this person's second process while the scheduler interleaves the operations.
	w.Devices[1] = &Device{App: process, Store: store, Keys: keys, ID: primary.ID}
	err := func() error {
		defer func() { w.Devices[1] = actualTeammate }()
		return w.ConcurrentCase(ctx, c)
	}()
	if err != nil {
		return fmt.Errorf("same user checkout=%t %+v: %w", otherCheckout, c, err)
	}
	if err := w.Tape.Observe("same-user-processes", []any{otherCheckout, c}, primary.ID); err != nil {
		return err
	}
	// The genuine teammate must also observe the exact result. Its checkpoint
	// was not advanced by either of the same-person processes.
	if err := w.Check(ctx, "default"); err != nil {
		return err
	}
	if err := primary.App.SyncSecrets(ctx, "default"); err != nil {
		return err
	}
	for i := range w.Devices {
		w.Restart(i)
	}
	return w.Check(ctx, "default")
}
