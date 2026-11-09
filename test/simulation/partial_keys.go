package simulation

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	agecrypto "filippo.io/age"
	"github.com/enbu-net/enbu/pkg/apperr"
	"github.com/enbu-net/enbu/pkg/config"
	"github.com/enbu-net/enbu/pkg/identity"
)

var partialKeyCases = []string{"signing", "current", "pending-before-approval", "pending-after-approval", "previous", "promotion-before", "promotion-after"}

// promotionFailure models the identity backend returning an error either before
// or after durable promotion. Filesystem rename recovery has native tests; here
// the App must remain usable with the durable current/pending/previous slots.
type promotionFailure struct {
	*Keys
	after bool
	calls int
}

func (k *promotionFailure) PromotePending(ws string) error {
	k.calls++
	if k.after {
		if err := k.Keys.PromotePending(ws); err != nil {
			return err
		}
	}
	return &identity.UnavailableError{Reason: "simulated interrupted key promotion"}
}

func (w *World) PartialKeys(ctx context.Context, kind string) error {
	d := w.Devices[1]
	admin := w.Devices[0].App
	cfg, err := config.LoadProjectFrom(admin.RepositoryDir)
	if err != nil {
		return err
	}
	ws, oldID := cfg.WorkspaceID, d.ID
	oldKey := d.Keys.state(ws).current
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
	denied := func(code apperr.Code, noKey bool) error {
		for _, run := range []func() error{
			func() error { _, err := d.App.ListSecrets(ctx, "default"); return err },
			func() error { return d.App.EditSecret(ctx, "default", "BASE", "must-not-commit") },
			func() error { return d.App.PullSecretsToFile(ctx, "default") },
			func() error { return d.App.SyncSecrets(ctx, "default") },
		} {
			err := run()
			if noKey {
				var noMatch *agecrypto.NoIdentityMatchError
				if !errors.As(err, &noMatch) {
					return fmt.Errorf("lost key was not a decryption failure: %w", err)
				}
			} else if err := requireCode(err, code); err != nil {
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
		result, err := d.App.InitializeRepository(ctx)
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
	switch kind {
	case "signing", "current":
		// Removing a slot models loss of its local metadata/material. A backend
		// whose metadata still exists but cannot unlock is the locked-device suite.
		if kind == "signing" {
			d.Keys.state(ws).signing = nil
		} else {
			d.Keys.state(ws).current = ""
		}
		w.Restart(1)
		d = w.Devices[1]
		if err := denied(apperr.CodeNotInitialized, false); err != nil {
			return err
		}
		if err := advanceTeam(); err != nil {
			return err
		}
		result, err := d.App.InitializeRepository(ctx)
		if err != nil {
			return err
		}
		if result.Founded {
			return fmt.Errorf("partial key loss refounded the workspace")
		}
		if kind == "signing" {
			if result.DeviceID == oldID || !result.Pending || result.KeyCreated {
				return fmt.Errorf("signing replacement inherited authority or replaced encryption: %+v", result)
			}
		} else {
			if result.DeviceID != oldID || result.Pending || !result.KeyCreated || result.CanDecrypt == nil || *result.CanDecrypt {
				return fmt.Errorf("new encryption key inherited decryption: %+v", result)
			}
			if err := denied("", true); err != nil {
				return err
			}
		}
		if err := readmit(); err != nil {
			return err
		}
	default:
		result, err := d.App.UpgradeIdentity(ctx)
		if err != nil {
			return err
		}
		if !result.Pending || result.DeviceID != oldID {
			return fmt.Errorf("non-admin upgrade bypassed approval")
		}
		pending := d.Keys.state(ws).pending
		if pending == "" || pending == oldKey {
			return fmt.Errorf("upgrade lacks a distinct pending key")
		}
		if kind == "pending-before-approval" {
			d.Keys.state(ws).pending = ""
			w.Restart(1)
			d = w.Devices[1]
			if err := w.Check(ctx, "default"); err != nil {
				return err
			}
		}
		if err := admin.ApproveMember(ctx, oldID); err != nil {
			return err
		}
		switch kind {
		case "pending-before-approval", "pending-after-approval":
			d.Keys.state(ws).pending = ""
			w.Restart(1)
			d = w.Devices[1]
			if err := denied("", true); err != nil {
				return err
			}
			if err := advanceTeam(); err != nil {
				return err
			}
			if err := readmit(); err != nil {
				return err
			}
		case "previous":
			if _, err := d.App.ListSecrets(ctx, "default"); err != nil {
				return err
			}
			if d.Keys.state(ws).previous != oldKey || d.Keys.state(ws).current != pending {
				return fmt.Errorf("approved key was not durably promoted")
			}
			d.Keys.state(ws).previous = ""
			w.Restart(1)
			d = w.Devices[1]
			if err := advanceTeam(); err != nil {
				return err
			}
		case "promotion-before", "promotion-after":
			fault := &promotionFailure{Keys: d.Keys, after: kind == "promotion-after"}
			d.App.Identities = fault
			for _, env := range []string{"default", "production"} {
				if err := w.Check(ctx, env); err != nil {
					return err
				}
			}
			if fault.calls == 0 {
				return fmt.Errorf("promotion fault was not reached")
			}
			current := oldKey
			if fault.after {
				current = pending
			}
			if d.Keys.state(ws).current != current {
				return fmt.Errorf("promotion error changed the wrong durable slot")
			}
			if err := advanceTeam(); err != nil {
				return err
			}
			w.Restart(1)
			d = w.Devices[1]
			if _, err := d.App.ListSecrets(ctx, "default"); err != nil {
				return err
			}
			if d.Keys.state(ws).current != pending || d.Keys.state(ws).pending != "" || d.Keys.state(ws).previous != oldKey {
				return fmt.Errorf("restart did not finish approved promotion")
			}
		default:
			return fmt.Errorf("unknown partial key case %q", kind)
		}
	}
	if kind != "signing" && d.ID != oldID {
		return fmt.Errorf("encryption-only recovery changed the signing identity")
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
