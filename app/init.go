package app

import (
	"context"
	"crypto/sha256"
	"errors"
	agecrypto "filippo.io/age"
	"fmt"
	"github.com/enbu-net/enbu/pkg/apperr"
	"github.com/enbu-net/enbu/pkg/config"
	"github.com/enbu-net/enbu/pkg/identity"
	"github.com/enbu-net/enbu/pkg/storage"
	"github.com/enbu-net/enbu/pkg/wsp"
	"github.com/opencontainers/go-digest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"uuid"
)

type InitResult struct {
	PublicKey   string `json:"public_key"`
	Username    string `json:"username"`
	Environment string `json:"environment"`
	WorkspaceID string `json:"workspace_id"`
	// ControlGenesis is the genesis this device trusts for the workspace.
	ControlGenesis string `json:"control_genesis"`
	Storage        string `json:"storage"`
	KeyCreated     bool   `json:"key_created"`
	Mode           string `json:"mode"`
	HasSecrets     bool   `json:"has_secrets"`
	CanDecrypt     *bool  `json:"can_decrypt"`
	DeviceID       string `json:"device_id"`
	Fingerprint    string `json:"fingerprint"`
	// Founded is set when this init created the workspace's genesis Control.
	Founded bool `json:"founded"`
	// Pending is set when this device is not yet in the workspace Control; an
	// admin must approve it.
	Pending bool `json:"pending"`
	// ReplacedGenesis is the genesis this device trusted before
	// AcceptNewGenesis replaced it, or "".
	ReplacedGenesis string   `json:"replaced_genesis,omitempty"`
	Warnings        []string `json:"-"`
}

func (a *App) InitializeRepository(ctx context.Context) (result *InitResult, err error) {
	defer apperr.NormalizeInto(&err)
	cfg, err := a.loadProject()
	missing := apperr.Is(err, apperr.CodeConfigNotFound)
	if err != nil && !missing {
		return nil, err
	}
	if missing {
		cfg = a.newProject(DefaultEnvironment)
	}
	if a.InitStorage != nil {
		cfg.Storage = *a.InitStorage
	}
	if a.StorageURL != "" {
		cfg.Storage.URL = a.StorageURL
	}
	if cfg.Storage.URL == "" {
		if cfg.Storage.URL, err = a.DefaultStorageURL(); err != nil {
			return nil, err
		}
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
			cfg.WorkspaceID = a.newID()
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
		return nil, identityError(err)
	}
	defer func() { _ = id.Close() }()
	signer, _, signerWarning, err := a.Identities.CreateSigner(cfg.WorkspaceID)
	if err != nil {
		return nil, identityError(err)
	}
	defer func() { _ = signer.Close() }()
	publicKey := id.Recipient().String()
	device := signer.Public().DeviceID()

	s := &session{app: a, store: store, cfg: cfg, workspace: cfg.WorkspaceID, ids: []agecrypto.Identity{id}, signer: signer, acceptNewGenesis: a.AcceptNewGenesis}
	if err := a.ensureControl(ctx, s, wsp.Principal{ID: device, Signing: signer.Public(), Recipient: publicKey, Admin: true}); err != nil {
		return nil, err
	}
	result = &InitResult{PublicKey: publicKey, Username: publicKey, Environment: cfg.CurrentEnvironment(), WorkspaceID: cfg.WorkspaceID, Storage: cfg.Storage.URL,
		KeyCreated: info.Created, Mode: "initialize", Founded: s.founded, DeviceID: string(device), Fingerprint: device.Fingerprint(),
		ControlGenesis: cfg.ControlGenesis, ReplacedGenesis: string(s.replaced.Genesis)}
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
		blob, err := wsp.NewJoinRequest(cfg.WorkspaceID, publicKey, a.now(), signer)
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
	_, err = s.readResource(ctx, s.resource(cfg.CurrentEnvironment()), nil, true)
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

// DefaultStorageURL is the storage a new workspace gets when none is given:
// a GHCR repository beside the GitHub repository named by the origin remote.
// It is used once, when init writes enbu.toml, and never derived again.
func (a *App) DefaultStorageURL() (_ string, err error) {
	defer apperr.NormalizeInto(&err)
	owner, repo, err := a.RepoDetector.LoadRepo()
	if err != nil {
		return "", apperr.Wrap(apperr.CodeInvalidArgument, "no storage given and the origin remote is not a GitHub repository; pass --storage", err, nil)
	}
	path := strings.ToLower(owner) + "/" + strings.ToLower(repo) + "-enbu"
	if !ociRepositoryName.MatchString(path) {
		// GitHub allows names OCI does not, such as ".github".
		return "", apperr.New(apperr.CodeInvalidArgument, "the GitHub repository name is not a valid GHCR repository name; pass --storage", nil)
	}
	return "oci://ghcr.io/" + path, nil
}

// ociRepositoryName is the OCI distribution spec's repository name grammar.
var ociRepositoryName = regexp.MustCompile(`^[a-z0-9]+((\.|_|__|-+)[a-z0-9]+)*(/[a-z0-9]+((\.|_|__|-+)[a-z0-9]+)*)*$`)

// ensureControl verifies the workspace's Control, creating the genesis Control
// when the storage has none and this repository has no trusted genesis yet. On
// return s.view and s.head describe the verified DAG.
func (a *App) ensureControl(ctx context.Context, s *session, founder wsp.Principal) error {
	if s.cfg.ControlGenesis == "" {
		// Accepting replaces a pin with the genesis enbu.toml names; with none
		// named there is nothing to accept, only a new workspace to found.
		if s.acceptNewGenesis {
			return apperr.New(apperr.CodeInvalidArgument, "--accept-new-genesis needs the control_genesis an admin shared in enbu.toml", nil)
		}
		// A device that already trusts a genesis for this workspace must not
		// found another one: emptied storage would otherwise re-root its trust.
		if pinned, err := a.trustRoot(s.workspace).Pinned(); err != nil {
			return err
		} else if pinned != (wsp.Root{}) {
			return wspError(&wsp.TrustRootChangedError{Pinned: pinned, Configured: wsp.Root{Workspace: s.workspace}})
		}
		// Storage must hold no workspace yet: with no trusted genesis there is
		// nothing to tell a founder's Control from an outsider's.
		for _, k := range []storage.Kind{storage.KindControl, storage.KindRequest} {
			if revs, err := s.store.Discover(ctx, k, ""); err != nil {
				return storageError(err)
			} else if len(revs) > 0 {
				return apperr.New(apperr.CodeIncompatibleStorage, "storage already holds a workspace; use the enbu.toml an admin shared, or an empty location", nil)
			}
		}

		blob, genesis, gerr := wsp.NewGenesis(s.workspace, founder, s.signer)
		if gerr != nil {
			return gerr
		}
		// Keep the exact signed bytes before publishing: a response can be lost
		// after storage commits, and hardware signatures cannot be regenerated.
		path, err := a.pendingGenesisPath(s.workspace, string(genesis))
		if err != nil {
			return err
		}
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			return err
		}
		f, err := os.CreateTemp(filepath.Dir(path), "founding-*")
		if err != nil {
			return err
		}
		tmp := f.Name()
		defer func() { _ = os.Remove(tmp) }()
		if _, err = f.Write(blob); err == nil {
			err = f.Sync()
		}
		closeErr := f.Close()
		if err != nil {
			return err
		}
		if closeErr != nil {
			return closeErr
		}
		if err := os.Rename(tmp, path); err != nil {
			return err
		}
		s.cfg.ControlGenesis = string(genesis)
		if err := a.saveProject(s.cfg); err != nil {
			return err
		}
		s.founded = true

	}
	path, err := a.pendingGenesisPath(s.workspace, s.cfg.ControlGenesis)
	if err != nil {
		return err
	}
	recovery := false
	if blob, err := os.ReadFile(path); err == nil {
		if _, err := wsp.VerifyGenesis(s.workspace, blob, digest.Digest(s.cfg.ControlGenesis)); err != nil {
			return wspError(err)
		}
		pinned, err := a.trustRoot(s.workspace).Pinned()
		if err != nil {
			return err
		}
		root := wsp.Root{Workspace: s.workspace, Genesis: digest.Digest(s.cfg.ControlGenesis)}
		if !s.acceptNewGenesis && pinned != (wsp.Root{}) && pinned != root {
			return wspError(&wsp.TrustRootChangedError{Pinned: pinned, Configured: root})
		}
		if err := wsp.PublishGenesis(ctx, s.store, blob); err != nil {
			return storageError(err)
		}
		recovery = true
		s.founded = pinned == (wsp.Root{})
	} else if !os.IsNotExist(err) {
		return err
	}

	// A genesis the repository trusts but storage lacks is reported by verifyControl
	// as incompatible storage; trust is never re-rooted silently.
	if err := a.verifyControl(ctx, s); err != nil {
		return err
	}
	if recovery {
		// Retain the exact founding bytes until verification and both trust
		// pins commit. A disconnect before this point must remain retryable.
		// Afterward leftover public bytes are harmless if cleanup fails.
		_ = os.Remove(path)
	}
	return nil
}

// identityError turns "this device has no backend for a key" into an error
// the user can act on: it carries the reason doctor would show and points at
// doctor, instead of surfacing as an internal error.
func identityError(err error) error {
	var unavailable *identity.UnavailableError
	if !errors.As(err, &unavailable) {
		return err
	}
	return apperr.Wrap(apperr.CodeIdentityUnavailable,
		"no usable identity backend on this device: "+unavailable.Reason+" (run 'enbu doctor' for details)", err, apperr.Params{"reason": unavailable.Reason})
}

// A recovery capability belongs to this workspace in this checkout, never
// another repository that happens to name the same genesis in enbu.toml.
func (a *App) pendingGenesisPath(workspace, genesis string) (string, error) {
	path, err := config.ProjectConfigPathFrom(a.RepositoryDir)
	if err != nil {
		return "", err
	}
	path, err = filepath.Abs(path)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(workspace + "\x00" + path + "\x00" + genesis))
	return filepath.Join(a.checkpointDir(), "founding", fmt.Sprintf("%x.cbor", sum)), nil
}
