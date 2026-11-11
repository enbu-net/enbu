package simulation

import (
	"context"
	"errors"
	"fmt"
	"reflect"

	agecrypto "filippo.io/age"
	"github.com/enbu-net/enbu/app"
	"github.com/enbu-net/enbu/pkg/age"
	"github.com/enbu-net/enbu/pkg/apperr"
	"github.com/enbu-net/enbu/pkg/config"
	"github.com/enbu-net/enbu/pkg/storage"
	"github.com/enbu-net/enbu/pkg/wsp"
	"github.com/opencontainers/go-digest"
)

// TeamIncident follows a release conflict through an employee's departure.
// The attacker retains their genuine signing/decryption keys and registry write
// access: denying their App calls alone cannot establish revocation safety.
func (w *World) TeamIncident(ctx context.Context) error {
	if len(w.Devices) < 3 {
		return fmt.Errorf("team incident requires three devices")
	}
	a := w.Devices[0].App
	if err := a.CreateEnvironment("production"); err != nil {
		return err
	}
	if err := w.Share(0); err != nil {
		return err
	}
	w.Model["production"] = map[string]string{"ENDPOINT": "release"}
	if err := a.AddSecret(ctx, "production", "ENDPOINT", "release"); err != nil {
		return err
	}
	if err := w.Check(ctx, "default"); err != nil {
		return err
	}
	if err := w.Check(ctx, "production"); err != nil {
		return err
	}
	// Two developers rotate the same credential independently; the release must
	// stop until the team explicitly chooses a value against the observed heads.
	if err := w.Batch(ctx, "publish", []func(int) error{
		func(int) error { return a.EditSecret(ctx, "default", "BASE", "developer-a") },
		func(int) error { return w.Devices[1].App.EditSecret(ctx, "default", "BASE", "developer-b") },
	}); err != nil {
		return err
	}
	for _, d := range w.Devices {
		if _, err := d.App.ListSecrets(ctx, "default"); requireCode(err, apperr.CodeSecretConflict) != nil {
			return fmt.Errorf("release conflict bypassed: %v", err)
		}
	}
	set, err := a.ListConflicts(ctx, "default")
	if err != nil {
		return err
	}
	if err := a.ResolveSecrets(ctx, "default", set.Heads, []app.SecretChoice{{Key: "BASE", Value: "reviewed-release"}}); err != nil {
		return err
	}
	w.Model["default"]["BASE"] = "reviewed-release"
	if err := w.Check(ctx, "default"); err != nil {
		return err
	}
	cfg, err := config.LoadProjectFrom(a.RepositoryDir)
	if err != nil {
		return err
	}
	view, err := wsp.LoadControl(ctx, w.Devices[0].Store, cfg.WorkspaceID, digest.Digest(cfg.ControlGenesis), nil)
	if err != nil {
		return err
	}
	// Replay a current member's correctly signed development state under the
	// production scope. This isolates resource binding from membership rejection.
	states, err := wsp.LoadStates(ctx, w.Devices[0].Store, view, cfg.WorkspaceID, cfg.Resource("default"))
	if err != nil {
		return err
	}
	for _, head := range states.Heads {
		signed, err := w.Devices[0].Store.FetchHead(ctx, storage.KindState, storage.StateScope(cfg.WorkspaceID, cfg.Resource("default")), head.Digest)
		if err != nil {
			return err
		}
		blob, err := wsp.ReadCiphertext(ctx, w.Devices[0].Store, head)
		if err != nil {
			return err
		}
		copied := storage.Object{Kind: storage.KindState, Scope: storage.StateScope(cfg.WorkspaceID, cfg.Resource("production")), Rev: head.Digest, Head: signed, Blobs: [][]byte{blob}}
		if err := w.Devices[2].Store.Publish(ctx, copied); err != nil {
			return err
		}
	}
	if err := w.Check(ctx, "production"); err != nil {
		return err
	}
	old, err := view.Head()
	if err != nil {
		return err
	}
	if err := a.RemoveMember(ctx, w.Devices[2].ID); err != nil {
		return err
	}
	// Current ciphertext in every environment must exclude the departed device.
	view, err = wsp.LoadControl(ctx, w.Devices[0].Store, cfg.WorkspaceID, digest.Digest(cfg.ControlGenesis), nil)
	if err != nil {
		return err
	}
	id, err := w.Devices[2].Keys.Load(cfg.WorkspaceID)
	if err != nil {
		return err
	}
	defer func() { _ = id.Close() }()
	for _, env := range []string{"default", "production"} {
		states, err := wsp.LoadStates(ctx, w.Devices[0].Store, view, cfg.WorkspaceID, cfg.Resource(env))
		if err != nil {
			return err
		}
		if len(states.Heads) == 0 {
			return fmt.Errorf("no reencrypted heads for %s", env)
		}
		for _, head := range states.Heads {
			blob, err := wsp.ReadCiphertext(ctx, w.Devices[0].Store, head)
			if err != nil {
				return err
			}
			_, err = age.Decrypt(blob, id)
			var noMatch *agecrypto.NoIdentityMatchError
			if !errors.As(err, &noMatch) {
				return fmt.Errorf("departed key decrypts %s: %v", env, err)
			}
		}
		if _, err := w.Devices[2].App.ListSecrets(ctx, env); requireCode(err, apperr.CodeNotMember) != nil {
			return fmt.Errorf("departed member reads %s: %v", env, err)
		}
	}
	// Publish genuinely signed poisoned branches using both the last authorized
	// Control and the new Control. The second is not a signature forgery either.
	for _, epoch := range []digest.Digest{old.Digest, ""} {
		poisoned := map[string]string{"BASE": "attacker", "BACKDOOR": "injected"}
		obj, err := w.publishNodeAtControl(ctx, 2, epoch, poisoned)
		if err != nil {
			return err
		}
		// A registry operator also relocates the same signed object into production.
		obj.Scope = storage.StateScope(cfg.WorkspaceID, cfg.Resource("production"))
		if err := w.Devices[2].Store.Publish(ctx, obj); err != nil {
			return err
		}
		for i, d := range w.Devices {
			if i == 2 {
				continue
			}
			w.Restart(i)
			d = w.Devices[i]
			for _, env := range []string{"default", "production"} {
				got, err := d.App.ListSecrets(ctx, env)
				if err != nil {
					return err
				}
				if !reflect.DeepEqual(got, w.Model[env]) {
					return fmt.Errorf("revoked author or relocated state accepted on device %d/%s", i, env)
				}
			}
		}
	}
	// Recovery must preserve the reviewed release and allow continued teamwork.
	for _, env := range []string{"default", "production"} {
		if err := w.Devices[1].App.AddSecret(ctx, env, "AFTER_INCIDENT", "legitimate"); err != nil {
			return err
		}
		w.Model[env]["AFTER_INCIDENT"] = "legitimate"
		if _, err := w.Devices[0].App.CompactHistory(ctx, env, 1); err != nil {
			return err
		}
	}
	// Readmission is explicit and must not resurrect either poisoned branch.
	if _, err := w.Devices[2].App.InitializeRepository(ctx, app.InitOptions{}); err != nil {
		return err
	}
	if err := w.Devices[0].App.ApproveMember(ctx, w.Devices[2].ID); err != nil {
		return err
	}
	for _, env := range []string{"default", "production"} {
		if err := w.Check(ctx, env); err != nil {
			return err
		}
	}
	return nil
}
