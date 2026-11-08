package simulation

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/enbu-net/enbu/app"
	"github.com/enbu-net/enbu/pkg/apperr"
	"github.com/enbu-net/enbu/pkg/config"
)

var partialKeyCases = []string{"lost"}

func (w *World) PartialKeys(ctx context.Context, kind string) error {
	d := w.Devices[1]
	admin := w.Devices[0].App
	cfg, err := config.LoadProjectFrom(admin.RepositoryDir)
	if err != nil {
		return err
	}
	ws, oldID := cfg.WorkspaceID, d.ID
	if err := admin.CreateEnvironment("production"); err != nil {
		return err
	}
	if err := admin.AddSecret(ctx, "production", "TOKEN", "before-recovery"); err != nil {
		return err
	}
	w.Model["production"] = map[string]string{"TOKEN": "before-recovery"}
	if err := admin.SwitchEnvironment("default"); err != nil {
		return err
	}
	if err := w.Share(0); err != nil {
		return err
	}
	for _, env := range []string{"default", "production"} {
		if err := w.Check(ctx, env); err != nil {
			return err
		}
	}
	path := filepath.Join(d.App.RepositoryDir, ".env")
	local := []byte("LOCAL_ONLY=personal\nBASE=before-recovery\n")
	if err := os.WriteFile(path, local, 0600); err != nil {
		return err
	}
	// Teammates continue publishing while the affected device is offline.
	advanceTeam := func() error {
		if err := admin.EditSecret(ctx, "production", "TOKEN", "teammate-during-recovery"); err != nil {
			return err
		}
		w.Model["production"]["TOKEN"] = "teammate-during-recovery"
		return nil
	}
	denied := func(code apperr.Code) error {
		for _, run := range []func() error{
			func() error { _, err := d.App.ListSecrets(ctx, "default"); return err },
			func() error { return d.App.EditSecret(ctx, "default", "BASE", "must-not-commit") },
			func() error { return d.App.PullSecretsToFile(ctx, "default") },
			func() error { return d.App.SyncSecrets(ctx, "default") },
		} {
			if err := requireCode(run(), code); err != nil {
				return err
			}
		}
		got, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if string(got) != string(local) {
			return fmt.Errorf("denied operation changed local dotenv")
		}
		return nil
	}
	// Explicit removal and approval provide a recovery path without trusting the
	// surviving private key to rewrite the signed recipient list on its own.
	readmit := func() error {
		if err := admin.RemoveMember(ctx, oldID); err != nil {
			return err
		}
		result, err := d.App.InitializeRepository(ctx, app.InitOptions{})
		if err != nil {
			return err
		}
		if !result.Pending || result.Founded {
			return fmt.Errorf("recovery bypassed approval: %+v", result)
		}
		d.ID = result.DeviceID
		if err := requireCode(d.App.AddSecret(ctx, "default", "UNAPPROVED", "x"), apperr.CodeNotMember); err != nil {
			return err
		}
		return admin.ApproveMember(ctx, d.ID)
	}
	if kind != "lost" {
		return fmt.Errorf("unknown partial key case %q", kind)
	}
	// Losing the device's key entry loses its encryption and signing keys
	// together. A backend whose entry still exists but cannot unlock is the
	// locked-device suite.
	delete(d.Keys.workspaces, ws)
	w.Restart(1)
	d = w.Devices[1]
	if err := denied(apperr.CodeNotInitialized); err != nil {
		return err
	}
	if err := advanceTeam(); err != nil {
		return err
	}
	result, err := d.App.InitializeRepository(ctx, app.InitOptions{})
	if err != nil {
		return err
	}
	if result.Founded || !result.Pending || !result.KeyCreated || result.DeviceID == oldID {
		return fmt.Errorf("a lost device inherited authority: %+v", result)
	}
	if err := readmit(); err != nil {
		return err
	}
	if err := w.Check(ctx, "default"); err != nil {
		return err
	}
	if err := w.Check(ctx, "production"); err != nil {
		return err
	}
	if err := d.App.AddSecret(ctx, "default", "RECOVERED", "explicitly-approved"); err != nil {
		return err
	}
	w.Model["default"]["RECOVERED"] = "explicitly-approved"
	if err := d.App.PullSecretsToFile(ctx, "default"); err != nil {
		return err
	}
	expected := clone(w.Model["default"])
	expected["LOCAL_ONLY"] = "personal"
	if err := w.checkOutput("partial-key-recovery-file", path, expected); err != nil {
		return err
	}
	members, err := admin.ListMembers(ctx)
	if err != nil {
		return err
	}
	for _, member := range members {
		if member.DeviceID == d.ID && member.Admin {
			return fmt.Errorf("recovery silently granted admin")
		}
	}
	for i := range w.Devices {
		w.Restart(i)
	}
	if err := w.Check(ctx, "production"); err != nil {
		return err
	}
	return w.Check(ctx, "default")
}
