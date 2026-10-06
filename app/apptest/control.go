package apptest

import (
	"bytes"
	"context"
	"errors"
	"time"

	"github.com/enbu-net/enbu/pkg/config"
	"github.com/enbu-net/enbu/pkg/identity"
	"github.com/enbu-net/enbu/pkg/signing"
	"github.com/enbu-net/enbu/pkg/storage"
	"github.com/enbu-net/enbu/pkg/wsp"
)

// KeyStore is the part of an identity store these helpers need. It matches
// app.IdentityStore without importing app, which would be a cycle for app's own tests.
type KeyStore interface {
	Create(workspaceID string) (identity.Identity, identity.PublicInfo, string, error)
	CreateSigner(workspaceID string) (signing.Signer, identity.SignerInfo, string, error)
}

// Control makes this device the founder of the workspace configured in repoDir:
// it writes the genesis Control and records its digest as control_genesis. It
// does nothing when the repository already has a genesis, so it is safe to call
// on a workspace that was initialized through the real flow.
func Control(ctx context.Context, store *storage.Store, repoDir string, ids KeyStore) error {
	cfg, err := config.LoadProjectFrom(repoDir)
	if err != nil {
		return err
	}
	if cfg.ControlGenesis != "" {
		return nil
	}
	id, _, _, err := ids.Create(cfg.WorkspaceID)
	if err != nil {
		return err
	}
	defer func() { _ = id.Close() }()
	signer, _, _, err := ids.CreateSigner(cfg.WorkspaceID)
	if err != nil {
		return err
	}
	defer func() { _ = signer.Close() }()
	founder := wsp.Principal{ID: signer.Public().DeviceID(), Signing: signer.Public(), Recipient: id.Recipient().String(), Admin: true}
	v, err := wsp.CreateControl(ctx, store, cfg.WorkspaceID, founder, signer)
	if err != nil {
		return err
	}
	cfg.ControlGenesis = string(v.Digest)
	return config.SaveProjectTo(repoDir, cfg)
}

// JoinRequest makes this device ask to join the workspace, as `enbu init` does
// for a device that is not a member. It returns the device id.
func JoinRequest(ctx context.Context, store *storage.Store, workspaceID string, ids KeyStore) (string, error) {
	id, _, _, err := ids.Create(workspaceID)
	if err != nil {
		return "", err
	}
	defer func() { _ = id.Close() }()
	signer, _, _, err := ids.CreateSigner(workspaceID)
	if err != nil {
		return "", err
	}
	defer func() { _ = signer.Close() }()
	request, err := wsp.NewJoinRequest(workspaceID, id.Recipient().String(), time.Now(), signer)
	if err != nil {
		return "", err
	}
	d, err := store.Blobs.Put(ctx, bytes.NewReader(request))
	if err != nil {
		return "", err
	}
	device := signer.Public().DeviceID()
	if err := store.Refs.Put(ctx, wsp.JoinRequestRef(device), d, ""); err != nil && !errors.Is(err, storage.ErrConflict) {
		return "", err
	}
	return string(device), nil
}
