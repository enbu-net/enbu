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
	if missing {
		// A fresh repository founds a new workspace. Joining an existing one needs
		// the enbu.toml an admin shares: it holds the workspace and the trusted
		// genesis, and nothing in storage can be trusted to name them.
		if cfg.WorkspaceID == "" {
			cfg.WorkspaceID = uuid.NewV4().String()
		}
	}
	if _, err := uuid.Parse(cfg.WorkspaceID); err != nil {
		return nil, fmt.Errorf("invalid workspace ID: %w", err)
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
	resource := cfg.Resource(cfg.CurrentEnvironment())
	if _, ok := s.head.Principal(device); !ok {
		// Not a member: leave a request an admin can pick from a list. It carries
		// no authority, so anyone able to write to storage can do the same.
		blob, err := wsp.NewJoinRequest(cfg.WorkspaceID, publicKey, time.Now(), signer)
		if err != nil {
			return nil, err
		}
		if _, err := wsp.PublishJoinRequest(ctx, store, blob); err != nil {
			return nil, storageError(err)
		}
		result.Mode, result.Pending = "join", true
		if revs, err := store.Discover(ctx, storage.KindState, storage.StateScope(cfg.WorkspaceID, resource)); err == nil && len(revs) > 0 {
			result.HasSecrets = true
		}
		return result, nil
	}
	_, err = s.readResource(ctx, cfg.CurrentEnvironment(), nil, true)
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
// return s.view and s.head describe the verified DAG.
func (a *App) ensureControl(ctx context.Context, s *session, founder wsp.Principal) error {
	if s.cfg.ControlGenesis == "" {
		// Storage must hold no workspace yet: with no trusted genesis there is
		// nothing to tell a founder's Control from an outsider's.
		for _, k := range []storage.Kind{storage.KindControl, storage.KindRequest} {
			if revs, err := s.store.Discover(ctx, k, ""); err != nil {
				return storageError(err)
			} else if len(revs) > 0 {
				return apperr.New(apperr.CodeIncompatibleStorage, "storage already holds a workspace; use the enbu.toml an admin shared, or an empty location", nil)
			}
		}
		// Record the trusted digest in enbu.toml before publishing the control.
		// The other order can leave a published control that this repository
		// never learned to trust, locking the founder out of their own workspace.
		blob, genesis, gerr := wsp.NewGenesis(s.workspace, founder, s.signer)
		if gerr != nil {
			return gerr
		}
		s.cfg.ControlGenesis = string(genesis)
		if err := a.saveProject(s.cfg); err != nil {
			s.cfg.ControlGenesis = ""
			return err // nothing has been published yet
		}
		if cerr := wsp.PublishGenesis(ctx, s.store, blob); cerr != nil {
			s.cfg.ControlGenesis = ""
			if serr := a.saveProject(s.cfg); serr != nil {
				return fmt.Errorf("could not undo the recorded control_genesis in enbu.toml, remove it by hand: %w", errors.Join(serr, cerr))
			}
			return storageError(cerr)
		}
	}
	// A genesis the repository trusts but storage lacks is reported by verifyControl
	// as incompatible storage; trust is never re-rooted silently.
	return a.verifyControl(ctx, s)
}
