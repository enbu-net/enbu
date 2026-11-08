package simulation

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	agecrypto "filippo.io/age"
	"github.com/enbu-net/enbu/pkg/age"
	"github.com/enbu-net/enbu/pkg/apperr"
	"github.com/enbu-net/enbu/pkg/config"
	"github.com/enbu-net/enbu/pkg/wsp"
	"github.com/opencontainers/go-digest"
)

// FirstMember starts before the ordinary all-member bootstrap. A real new
// teammate has never held a key that can decrypt the founder's old ciphertext.
func (w *World) FirstMember(ctx context.Context) error {
	ctx = wsp.WithSerialHeadReads(ctx)
	founder := w.Devices[0]
	result, err := founder.App.InitializeRepository(ctx)
	if err != nil {
		return err
	}
	if !result.Founded || !result.KeyCreated || result.Pending {
		return fmt.Errorf("invalid first-founder result: %+v", result)
	}
	founder.ID = result.DeviceID
	for _, env := range []string{"default", "production", "staging"} {
		if env != "default" {
			if err := founder.App.CreateEnvironment(env); err != nil {
				return err
			}
		}
		if err := founder.App.AddSecret(ctx, env, "ENDPOINT", env+"-initial"); err != nil {
			return err
		}
		if err := founder.App.EditSecret(ctx, env, "ENDPOINT", env+"-current"); err != nil {
			return err
		}
		w.Model[env] = map[string]string{"ENDPOINT": env + "-current"}
	}
	if err := founder.App.SwitchEnvironment("default"); err != nil {
		return err
	}
	cfg, err := config.LoadProjectFrom(founder.App.RepositoryDir)
	if err != nil {
		return err
	}
	view, err := wsp.LoadControl(ctx, founder.Store, cfg.WorkspaceID, digest.Digest(cfg.ControlGenesis), nil)
	if err != nil {
		return err
	}
	states, err := wsp.LoadStates(ctx, founder.Store, view, cfg.WorkspaceID, cfg.Resource("default"))
	if err != nil {
		return err
	}
	if len(states.Heads) != 1 {
		return fmt.Errorf("founder history is not linear")
	}
	oldCiphertext, err := wsp.ReadCiphertext(ctx, founder.Store, states.Heads[0])
	if err != nil {
		return err
	}
	if err := w.Share(0); err != nil {
		return err
	}
	for i := 1; i < len(w.Devices); i++ {
		d := w.Devices[i]
		result, err := d.App.InitializeRepository(ctx)
		if err != nil {
			return err
		}
		d.ID = result.DeviceID
		if !result.Pending || !result.KeyCreated || !result.HasSecrets {
			return fmt.Errorf("late joiner result: %+v", result)
		}
		localFile := filepath.Join(d.App.RepositoryDir, ".env")
		if err := os.WriteFile(localFile, []byte("LOCAL_ONLY=personal\n"), 0600); err != nil {
			return err
		}
		for _, env := range []string{"default", "production", "staging"} {
			if _, err := d.App.ListSecrets(ctx, env); requireCode(err, apperr.CodeNotMember) != nil {
				return fmt.Errorf("unapproved newcomer read %s: %v", env, err)
			}
		}
		if err := requireCode(d.App.PullSecretsToFile(ctx, "default"), apperr.CodeNotMember); err != nil {
			return err
		}
		if err := w.checkOutput("pending-onboarding-file", localFile, map[string]string{"LOCAL_ONLY": "personal"}); err != nil {
			return err
		}
		if err := founder.App.ApproveMember(ctx, d.ID); err != nil {
			return err
		}
		id, err := d.Keys.Load(cfg.WorkspaceID)
		if err != nil {
			return err
		}
		_, err = age.Decrypt(oldCiphertext, id)
		_ = id.Close()
		var noMatch *agecrypto.NoIdentityMatchError
		if !errors.As(err, &noMatch) {
			return fmt.Errorf("newcomer decrypted pre-join ciphertext: %v", err)
		}
		if err := d.App.AddSecret(ctx, "production", fmt.Sprintf("NEWCOMER_%d", i), "acknowledged"); err != nil {
			return err
		}
		w.Model["production"][fmt.Sprintf("NEWCOMER_%d", i)] = "acknowledged"
	}
	for _, env := range []string{"default", "production", "staging"} {
		if err := w.Check(ctx, env); err != nil {
			return err
		}
	}
	return w.Tape.Observe("first-member-onboarding", len(w.Devices), w.Model)
}
