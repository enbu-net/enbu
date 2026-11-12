package app

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
	"uuid"

	agecrypto "filippo.io/age"
	"github.com/enbu-net/enbu/pkg/apperr"
	"github.com/enbu-net/enbu/pkg/config"
	"github.com/enbu-net/enbu/pkg/identity"
	"github.com/enbu-net/enbu/pkg/keystore"
	"github.com/enbu-net/enbu/pkg/storage"
	"github.com/enbu-net/enbu/pkg/wsp"
	"github.com/opencontainers/go-digest"
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

// InitOptions are what `enbu init` takes besides the repository.
type InitOptions struct {
	// Storage is where to found the workspace, with the options enbu.toml
	// keeps for it. Nil keeps enbu.toml's storage, or DefaultStorageURL's.
	Storage *config.StorageConfig
	// AcceptNewGenesis replaces the genesis this device pinned for the
	// workspace with the one enbu.toml names. Only a person who confirmed the
	// workspace was re-founded sets it.
	AcceptNewGenesis bool
}

// InitializeRepository sets this device up in the repository: it founds a
// workspace, or joins the one enbu.toml names, and keeps the files a pull
// writes out of Git.
func (a *App) InitializeRepository(ctx context.Context, opts InitOptions) (result *InitResult, err error) {
	defer apperr.NormalizeInto(&err)
	result, cfg, err := a.initializeRepository(ctx, opts)
	if err != nil {
		return nil, err
	}
	if err := a.ensureGitignore(cfg); err != nil {
		result.Warnings = append(result.Warnings, fmt.Sprintf("failed to update .gitignore: %v", err))
	}
	return result, nil
}

func (a *App) initializeRepository(ctx context.Context, opts InitOptions) (*InitResult, *config.ProjectConfig, error) {
	cfg, err := a.loadProject()
	missing := apperr.Is(err, apperr.CodeConfigNotFound)
	if err != nil && !missing {
		return nil, nil, err
	}
	if missing {
		cfg = a.newProject(DefaultEnvironment)
	}
	originalStorage := cfg.Storage
	if opts.Storage != nil {
		cfg.Storage = *opts.Storage
	}
	if a.StorageURL != "" {
		cfg.Storage.URL = a.StorageURL
	}
	if cfg.ControlGenesis != "" && cfg.Storage != originalStorage {
		return nil, nil, apperr.New(apperr.CodeConfigProtected, "use enbu storage migrate to change established storage", apperr.Params{"key": "storage"})
	}
	if cfg.Storage.URL == "" {
		if cfg.Storage.URL, err = a.DefaultStorageURL(); err != nil {
			return nil, nil, err
		}
	}
	store, err := a.openStorage(ctx, cfg)
	if err != nil {
		return nil, nil, err
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
		return nil, nil, fmt.Errorf("invalid workspace ID: %w", err)
	}
	// Save the workspace binding before registration, so a failed registration
	// retries the same local identity rather than generating another key.
	if err := a.saveProject(cfg); err != nil {
		return nil, nil, err
	}
	d, info, warning, err := a.Identities.Create(cfg.WorkspaceID)
	if err != nil {
		return nil, nil, identityError(err)
	}
	defer func() { _ = d.Close() }()
	id, signer := d.Identity, d.Signer
	publicKey := id.Recipient().String()
	device := signer.Public().DeviceID()

	s := &session{app: a, store: store, cfg: cfg, workspace: cfg.WorkspaceID, id: id, signer: signer, acceptNewGenesis: opts.AcceptNewGenesis}
	if err := a.ensureControl(ctx, s, wsp.Principal{ID: device, Signing: signer.Public(), Recipient: publicKey, Admin: true}); err != nil {
		return nil, nil, err
	}
	result := &InitResult{PublicKey: publicKey, Username: publicKey, Environment: cfg.CurrentEnvironment(), WorkspaceID: cfg.WorkspaceID, Storage: cfg.Storage.URL,
		KeyCreated: info.Created, Mode: "initialize", Founded: s.founded, DeviceID: string(device), Fingerprint: device.Fingerprint(),
		ControlGenesis: cfg.ControlGenesis, ReplacedGenesis: string(s.replaced.Genesis)}
	if warning != "" {
		result.Warnings = append(result.Warnings, warning)
		a.emit(warning)
	}
	resource := cfg.Resource(cfg.CurrentEnvironment())
	if _, ok := s.head.Principal(device); !ok {
		// Not a member: leave a request an admin can pick from a list. It carries
		// no authority, so anyone able to write to storage can do the same.
		// A removed device may ask again with a new key. Remove its own
		// obsolete signed requests first, otherwise approval sees two
		// different recipients. Never choose a request by its untrusted
		// listing order or timestamp.
		requests, err := wsp.ListJoinRequests(ctx, store, cfg.WorkspaceID)
		if err != nil {
			return nil, nil, wspError(err)
		}
		for _, request := range requests {
			if request.DeviceID() == device && request.Recipient != publicKey {
				if err := store.Delete(ctx, storage.KindRequest, "", request.Rev); err != nil && !errors.Is(err, storage.ErrUnsupported) && !errors.Is(err, storage.ErrNotFound) {
					return nil, nil, storageError(err)
				}
			}
		}
		blob, err := wsp.NewJoinRequest(cfg.WorkspaceID, publicKey, a.now(), signer)
		if err != nil {
			return nil, nil, err
		}
		if _, err := wsp.PublishJoinRequest(ctx, store, blob); err != nil {
			return nil, nil, storageError(err)
		}
		result.Mode, result.Pending = "join", true
		if revs, err := store.Discover(ctx, storage.KindState, storage.StateScope(cfg.WorkspaceID, resource)); err == nil && len(revs) > 0 {
			result.HasSecrets = true
		}
		return result, cfg, nil
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
			return nil, nil, err
		}
		result.Mode, result.HasSecrets = "join", true
		result.CanDecrypt = new(false)
	}
	return result, cfg, nil
}

// DefaultStorageURL is the storage a new workspace gets when none is given:
// a GHCR repository beside the GitHub origin, or under the signed-in account
// using the folder name when there is no usable GitHub origin.
// It is used once, when init writes enbu.toml, and never derived again.
func (a *App) DefaultStorageURL() (_ string, err error) {
	defer apperr.NormalizeInto(&err)
	owner, repo, repoErr := a.RepoDetector.LoadRepo()
	path := strings.ToLower(owner) + "/" + strings.ToLower(repo) + "-enbu"
	if repoErr == nil && ociRepositoryName.MatchString(path) {
		return "oci://ghcr.io/" + path, nil
	}
	if a.TokenProvider == nil {
		return "", apperr.New(apperr.CodeInvalidArgument, "no GHCR account available; sign in or pass --storage", nil)
	}
	_, username, tokenErr := a.TokenProvider.LoadToken()
	if tokenErr != nil {
		return "", apperr.Wrap(apperr.CodeNotAuthenticated, "sign in to use GHCR or pass --storage", tokenErr, nil)
	}
	dir, err := filepath.Abs(a.RepositoryDir)
	if err != nil {
		return "", err
	}
	name := strings.Trim(ghcrFolderSeparator.ReplaceAllString(strings.ToLower(filepath.Base(dir)), "-"), "-")
	if name == "" {
		name = "workspace"
	}
	path = strings.ToLower(username) + "/" + name + "-enbu"
	if username == "" || !ociRepositoryName.MatchString(path) {
		return "", apperr.New(apperr.CodeInvalidArgument, "no valid GHCR account available; sign in or pass --storage", nil)
	}
	return "oci://ghcr.io/" + path, nil
}

// ociRepositoryName is the OCI distribution spec's repository name grammar.
var ghcrFolderSeparator = regexp.MustCompile(`[^a-z0-9]+`)

var ociRepositoryName = regexp.MustCompile(`^[a-z0-9]+((\.|_|__|-+)[a-z0-9]+)*(/[a-z0-9]+((\.|_|__|-+)[a-z0-9]+)*)*$`)

// ensureControl verifies the workspace's Control, creating the genesis Control
// when the storage has none and this repository has no trusted genesis yet. On
// return s.view and s.head describe the verified DAG.
func (a *App) ensureControl(ctx context.Context, s *session, founder wsp.Principal) error {
	pinned, err := a.trust().Pinned(s.workspace)
	if err != nil && !s.acceptNewGenesis {
		return err
	}
	if s.cfg.ControlGenesis == "" {
		// Accepting replaces a pin with the genesis enbu.toml names; with none
		// named there is nothing to accept, only a new workspace to found.
		if s.acceptNewGenesis {
			return apperr.New(apperr.CodeInvalidArgument, "--accept-new-genesis needs the control_genesis an admin shared in enbu.toml", nil)
		}
		// A device that already trusts a genesis for this workspace must not
		// found another one: emptied storage would otherwise re-root its trust.
		if pinned != (wsp.Root{}) {
			return wspError(&wsp.TrustRootChangedError{Pinned: pinned, Configured: wsp.Root{Workspace: s.workspace}})
		}
		genesis, err := a.foundGenesis(ctx, s, founder)
		if err != nil {
			return err
		}
		s.cfg.ControlGenesis = string(genesis)
		if err := a.saveProject(s.cfg); err != nil {
			return err
		}
		s.founded = true
	} else if !s.acceptNewGenesis && pinned == (wsp.Root{}) {
		// A genesis this device signed and has not pinned yet is its own
		// founding, left by an attempt that stopped before pinning it. Only
		// its signing key can sign one, so this hands trust to nobody else.
		// A genesis storage lacks falls through to verifyControl, which reports
		// it; any other storage failure is returned so it can be retried.
		blob, err := s.store.FetchHead(ctx, storage.KindControl, "", digest.Digest(s.cfg.ControlGenesis))
		if err != nil && !errors.Is(err, storage.ErrNotFound) {
			return storageError(err)
		}
		if err == nil {
			v, err := wsp.VerifyGenesis(s.workspace, blob, digest.Digest(s.cfg.ControlGenesis))
			s.founded = err == nil && v.Author == s.self()
		}
	}
	// A genesis the repository trusts but storage lacks is reported by verifyControl
	// as incompatible storage; trust is never re-rooted silently.
	return a.verifyControl(ctx, s)
}

// foundGenesis publishes the genesis Control of a new workspace. Storage must
// hold no workspace yet: with no trusted genesis there is nothing to tell a
// founder's Control from an outsider's. The one exception is a genesis this
// device signed itself, left by an attempt whose publish reply was lost.
func (a *App) foundGenesis(ctx context.Context, s *session, founder wsp.Principal) (digest.Digest, error) {
	own, err := wsp.FindGenesis(ctx, s.store, s.workspace, s.self())
	if err != nil {
		return "", wspError(err)
	}
	if own != nil {
		return own.Digest, nil
	}
	for _, k := range []storage.Kind{storage.KindControl, storage.KindRequest} {
		if revs, err := s.store.Discover(ctx, k, ""); err != nil {
			return "", storageError(err)
		} else if len(revs) > 0 {
			return "", apperr.New(apperr.CodeIncompatibleStorage, "storage already holds a workspace; use the enbu.toml an admin shared, or an empty location", nil)
		}
	}
	blob, genesis, err := wsp.NewGenesis(s.workspace, founder, s.signer)
	if err != nil {
		return "", err
	}
	if err := wsp.PublishGenesis(ctx, s.store, blob); err != nil {
		return "", storageError(err)
	}
	return genesis, nil
}

// identityError turns "this device has no backend for a key" into an error
// the user can act on: it carries the reason doctor would show and points at
// doctor, instead of surfacing as an internal error.
func identityError(err error) error {
	var unavailable *identity.UnavailableError
	if !errors.As(err, &unavailable) {
		return err
	}
	if errors.Is(err, keystore.ErrLocked) {
		return apperr.Wrap(apperr.CodeKeyringLocked, unavailable.Reason, err, nil)
	}
	return apperr.Wrap(apperr.CodeIdentityUnavailable,
		"no usable identity backend on this device: "+unavailable.Reason+" (run 'enbu doctor' for details)", err, apperr.Params{"reason": unavailable.Reason})
}
