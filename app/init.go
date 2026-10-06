package app

import (
	"context"
	"errors"
	agecrypto "filippo.io/age"
	"fmt"
	"github.com/enbu-net/enbu/pkg/apperr"
	"github.com/enbu-net/enbu/pkg/config"
	"github.com/enbu-net/enbu/pkg/storage"
	"github.com/enbu-net/enbu/pkg/wsp"
	"time"
	"uuid"
)

type InitResult struct {
	PublicKey   string `json:"public_key"`
	Username    string `json:"username"`
	Environment string `json:"environment"`
	WorkspaceID string `json:"workspace_id"`
	Storage     string `json:"storage"`
	KeyCreated  bool   `json:"key_created"`
	Mode        string `json:"mode"`
	HasSecrets  bool   `json:"has_secrets"`
	CanDecrypt  *bool  `json:"can_decrypt"`
	DeviceID    string `json:"device_id"`
	Fingerprint string `json:"fingerprint"`
	// Pending is set when this device is not yet in the workspace Control; an
	// admin must approve it.
	Pending  bool     `json:"pending"`
	Warnings []string `json:"-"`
}

func (a *App) InitializeRepository(ctx context.Context) (result *InitResult, err error) {
	defer apperr.NormalizeInto(&err)
	cfg, err := a.loadProject()
	missing := apperr.Is(err, apperr.CodeConfigNotFound)
	if err != nil && !missing {
		return nil, err
	}
	if missing {
		cfg = config.NewProjectWithEnvironment(DefaultEnvironment)
	}
	if a.InitStorage != nil {
		cfg.Storage = *a.InitStorage
	}
	if a.StorageURL != "" {
		cfg.Storage.URL = a.StorageURL
	}
	store, err := a.openStorage(ctx, cfg)
	if err != nil {
		return nil, err
	}
	metadata, _, err := getRef(ctx, store, workspaceKey)
	if errors.Is(err, storage.ErrNotFound) {
		if detector, ok := store.Refs.(storage.LegacyDetector); ok {
			legacy, derr := detector.HasLegacy(ctx)
			if derr != nil {
				return nil, derr
			}
			if legacy {
				return nil, apperr.New(apperr.CodeInvalidArgument, "storage was written by an older enbu version and cannot be read; use an empty location or migrate it manually", nil)
			}
		}
		if cfg.WorkspaceID == "" {
			cfg.WorkspaceID = uuid.NewV4().String()
		}
		if _, err := uuid.Parse(cfg.WorkspaceID); err != nil {
			return nil, err
		}
		err = putRef(ctx, store, workspaceKey, []byte(cfg.WorkspaceID), "")
		if errors.Is(err, storage.ErrConflict) {
			metadata, _, err = getRef(ctx, store, workspaceKey)
		} else if err == nil {
			metadata = []byte(cfg.WorkspaceID)
		}
	}
	if err != nil {
		return nil, storageError(err)
	}
	if _, err := uuid.Parse(string(metadata)); err != nil {
		return nil, fmt.Errorf("invalid stored workspace ID: %w", err)
	}
	if missing {
		cfg.WorkspaceID = string(metadata)
	}
	if cfg.WorkspaceID != string(metadata) {
		return nil, apperr.New(apperr.CodeInvalidArgument, "storage belongs to a different workspace", nil)
	}
	// Save the workspace binding before registration, so a failed registration
	// retries the same local identity rather than generating another key.
	if err := a.saveProject(cfg); err != nil {
		return nil, err
	}
	id, info, warning, err := a.Identities.Create(cfg.WorkspaceID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = id.Close() }()
	signer, _, signerWarning, err := a.Identities.CreateSigner(cfg.WorkspaceID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = signer.Close() }()
	publicKey := id.Recipient().String()
	device := signer.Public().DeviceID()

	s := &session{app: a, store: store, cfg: cfg, workspace: cfg.WorkspaceID, ids: []agecrypto.Identity{id}, signer: signer}
	if err := a.ensureControl(ctx, s, wsp.Principal{ID: device, Signing: signer.Public(), Recipient: publicKey, Admin: true}); err != nil {
		return nil, err
	}
	result = &InitResult{PublicKey: publicKey, Username: publicKey, Environment: cfg.CurrentEnvironment(), WorkspaceID: cfg.WorkspaceID, Storage: cfg.Storage.URL,
		KeyCreated: info.Created, Mode: "initialize", DeviceID: string(device), Fingerprint: device.Fingerprint()}
	for _, w := range []string{warning, signerWarning} {
		if w != "" {
			result.Warnings = append(result.Warnings, w)
			a.emit(w)
		}
	}
	ref := secretsTag(cfg.CurrentEnvironment())
	if _, ok := s.head.Principal(device); !ok {
		// Not a member: leave a request an admin can pick from a list. It carries
		// no authority, so anyone able to write to storage can do the same.
		blob, err := wsp.NewJoinRequest(cfg.WorkspaceID, publicKey, time.Now(), signer)
		if err != nil {
			return nil, err
		}
		if err := putRef(ctx, store, wsp.JoinRequestRef(device), blob, ""); err != nil && !errors.Is(err, storage.ErrConflict) {
			return nil, storageError(err)
		}
		result.Mode, result.Pending = "join", true
		if _, _, err := store.Refs.Get(ctx, ref); err == nil {
			result.HasSecrets = true
		}
		return result, nil
	}
	_, err = s.readState(ctx, ref, cfg.CurrentEnvironment(), true)
	switch {
	case err == nil:
		result.Mode, result.HasSecrets = "join", true
		result.CanDecrypt = new(true)
	case IsNotFoundError(err):
	default:
		var noMatch *agecrypto.NoIdentityMatchError
		if !errors.As(err, &noMatch) {
			return nil, err
		}
		result.Mode, result.HasSecrets = "join", true
		result.CanDecrypt = new(false)
	}
	return result, nil
}

// ensureControl verifies the workspace's Control, creating the genesis Control
// when the storage has none and this repository has no trusted genesis yet. On
// return s.head is the verified head.
func (a *App) ensureControl(ctx context.Context, s *session, founder wsp.Principal) error {
	_, _, err := s.store.Refs.Get(ctx, wsp.ControlRef)
	if errors.Is(err, storage.ErrNotFound) {
		if s.cfg.ControlGenesis != "" {
			// Never re-root trust silently: enbu.toml names a genesis this storage lacks.
			return apperr.New(apperr.CodeIncompatibleStorage, "storage has no workspace control but enbu.toml expects one; use the original storage", nil)
		}
		if refs, lerr := s.store.Refs.List(ctx, "secrets-"); lerr != nil {
			return storageError(lerr)
		} else if len(refs) > 0 {
			return apperr.New(apperr.CodeIncompatibleStorage, "storage was written without a workspace control and cannot be used; use an empty location", nil)
		}
		v, cerr := wsp.CreateControl(ctx, s.store, s.workspace, founder, s.signer)
		switch {
		case cerr == nil:
			s.cfg.ControlGenesis = string(v.Digest)
			if err := a.saveProject(s.cfg); err != nil {
				return err
			}
		case !errors.Is(cerr, storage.ErrConflict):
			return storageError(cerr)
		}
		// On conflict another device created it first; verify theirs below.
	} else if err != nil {
		return storageError(err)
	}
	head, err := a.verifyControl(ctx, s)
	if err != nil {
		return err
	}
	s.head = head
	return nil
}
