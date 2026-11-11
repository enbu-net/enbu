package simulation

import (
	"context"
	"fmt"
	"reflect"

	"github.com/enbu-net/enbu/app"
	"github.com/enbu-net/enbu/pkg/apperr"
	"github.com/enbu-net/enbu/pkg/config"
	"github.com/enbu-net/enbu/pkg/storage"
	"github.com/enbu-net/enbu/pkg/storage/storagetest"
	"github.com/enbu-net/enbu/pkg/wsp"
)

// Refounding models deliberately replacing a lost workspace with a new trusted
// root and a different founder. Sharing configuration alone must never opt any
// existing device into that change, including the former admin.
func (w *World) Refounding(ctx context.Context) error {
	old, err := config.LoadProjectFrom(w.Devices[0].App.RepositoryDir)
	if err != nil {
		return err
	}
	if err := w.Check(ctx, "default"); err != nil {
		return err
	}
	signer, err := w.Devices[1].Keys.LoadSigner(old.WorkspaceID)
	if err != nil {
		return err
	}
	defer func() { _ = signer.Close() }()
	key, err := w.Devices[1].Keys.Load(old.WorkspaceID)
	if err != nil {
		return err
	}
	defer func() { _ = key.Close() }()
	genesis, root, err := wsp.NewGenesis(old.WorkspaceID, wsp.Principal{ID: signer.Public().DeviceID(), Signing: signer.Public(), Recipient: key.Recipient().String(), Admin: true}, signer)
	if err != nil {
		return err
	}
	if string(root) == old.ControlGenesis {
		return fmt.Errorf("replacement root did not change")
	}
	previousStore := w.Devices[0].Store.Store
	replacement := storagetest.NewMemory()
	for _, d := range w.Devices {
		d.Store.Store = replacement
	}
	if err := w.Devices[1].Store.Publish(ctx, storage.Object{Kind: storage.KindControl, Rev: root, Head: genesis}); err != nil {
		return err
	}
	next := *old
	next.ControlGenesis = string(root)
	if err := config.SaveProjectTo(w.Devices[1].App.RepositoryDir, &next); err != nil {
		return err
	}
	if err := w.Share(1); err != nil {
		return err
	}
	if err := w.Tape.Observe("replace-workspace-storage", old.ControlGenesis, root); err != nil {
		return err
	}
	for _, d := range w.Devices {
		if _, err := d.App.ListSecrets(ctx, "default"); requireCode(err, apperr.CodeTrustRootChanged) != nil {
			return fmt.Errorf("shared root silently trusted: %v", err)
		}
	}
	// A failed explicit acceptance must not pin an unreachable replacement.
	d := w.Devices[1]
	d.Store.Arm(Fault{"head", 1, "before"})
	if _, err := d.App.InitializeRepository(ctx, app.InitOptions{AcceptNewGenesis: true}); err == nil {
		return fmt.Errorf("unreachable replacement accepted")
	}
	d.Store.Arm(Fault{})
	w.Restart(1)
	d = w.Devices[1]
	d.Store.Store = previousStore
	if err := config.SaveProjectTo(d.App.RepositoryDir, old); err != nil {
		return err
	}
	got, err := d.App.ListSecrets(ctx, "default")
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(got, w.Model["default"]) {
		return fmt.Errorf("failed root acceptance changed old trusted data")
	}
	d.Store.Store = replacement
	if err := config.SaveProjectTo(d.App.RepositoryDir, &next); err != nil {
		return err
	}
	// Every person confirms the root independently; confirmation is not membership.
	for i, d := range w.Devices {
		result, err := d.App.InitializeRepository(ctx, app.InitOptions{AcceptNewGenesis: true})
		if err != nil {
			return err
		}
		if result.ReplacedGenesis != old.ControlGenesis || result.Pending != (i != 1) {
			return fmt.Errorf("replacement result on device %d: %+v", i, result)
		}
		w.Restart(i)
	}
	for i := range w.Devices {
		if i != 1 {
			if err := w.Devices[1].App.ApproveMember(ctx, w.Devices[i].ID); err != nil {
				return err
			}
		}
	}
	w.Model["default"] = map[string]string{}
	if err := w.Check(ctx, "default"); err != nil {
		return err
	}
	// Previous administrators retain ordinary data access, but no old authority.
	if err := requireCode(w.Devices[0].App.SetAdmin(ctx, w.Devices[0].ID, true), apperr.CodeAccessDenied); err != nil {
		return err
	}
	if err := w.Devices[0].App.AddSecret(ctx, "default", "AFTER_REFOUND", "new workspace"); err != nil {
		return err
	}
	w.Model["default"]["AFTER_REFOUND"] = "new workspace"
	if err := config.SaveProjectTo(w.Devices[0].App.RepositoryDir, old); err != nil {
		return err
	}
	if _, err := w.Devices[0].App.ListSecrets(ctx, "default"); requireCode(err, apperr.CodeTrustRootChanged) != nil {
		return fmt.Errorf("old root silently restored: %v", err)
	}
	if err := config.SaveProjectTo(w.Devices[0].App.RepositoryDir, &next); err != nil {
		return err
	}
	// Subsequent generated workloads reserve device 0 as a continuing admin.
	// Restore that role only through a new-root admin's explicit delegation.
	if err := w.Devices[1].App.SetAdmin(ctx, w.Devices[0].ID, true); err != nil {
		return err
	}
	return w.Check(ctx, "default")
}
