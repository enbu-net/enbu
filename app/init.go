package app

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"uuid"

	agecrypto "filippo.io/age"
	"github.com/enbu-net/enbu/pkg/apperr"
	"github.com/enbu-net/enbu/pkg/config"
	"github.com/enbu-net/enbu/pkg/fsutil"
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
	if opts.Storage != nil {
		cfg.Storage = *opts.Storage
	}
	if a.StorageURL != "" {
		cfg.Storage.URL = a.StorageURL
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
	id, info, warning, err := a.Identities.Create(cfg.WorkspaceID)
	if err != nil {
		return nil, nil, identityError(err)
	}
	defer func() { _ = id.Close() }()
	signer, _, signerWarning, err := a.Identities.CreateSigner(cfg.WorkspaceID)
	if err != nil {
		return nil, nil, identityError(err)
	}
	defer func() { _ = signer.Close() }()
	publicKey := id.Recipient().String()
	device := signer.Public().DeviceID()

	s := &session{app: a, store: store, cfg: cfg, workspace: cfg.WorkspaceID, ids: []agecrypto.Identity{id}, signer: signer, acceptNewGenesis: opts.AcceptNewGenesis}
	if err := a.ensureControl(ctx, s, wsp.Principal{ID: device, Signing: signer.Public(), Recipient: publicKey, Admin: true}); err != nil {
		return nil, nil, err
	}
	result := &InitResult{PublicKey: publicKey, Username: publicKey, Environment: cfg.CurrentEnvironment(), WorkspaceID: cfg.WorkspaceID, Storage: cfg.Storage.URL,
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
		// A removed device may have upgraded its encryption key since its
		// original join. Remove its own obsolete signed requests before
		// asking again, otherwise approval sees two different recipients.
		// Never choose a request by its untrusted listing order or timestamp.
		requests, err := wsp.ListJoinRequests(ctx, store, cfg.WorkspaceID)
		if err != nil {
			return nil, nil, wspError(err)
		}
		for _, request := range requests {
			if request.DeviceID() == device && request.Replaces == "" && request.Recipient != publicKey {
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
		if err := fsutil.MkdirAll(filepath.Dir(path), 0700); err != nil {
			return err
		}
		previousRepo := wsp.Root{}
		if repo := a.repositoryTrustRoot(); repo != nil {
			previousRepo, err = repo.Pinned()
			if err != nil {
				return err
			}
		}
		repository, err := a.foundingRepository()
		if err != nil {
			return err
		}
		pending, err := json.Marshal(pendingFounding{Root: wsp.Root{Workspace: s.workspace, Genesis: genesis}, Repository: repository, PreviousRepo: previousRepo, Genesis: blob})
		if err != nil {
			return err
		}
		f, err := os.CreateTemp(filepath.Dir(path), "founding-*")
		if err != nil {
			return err
		}
		tmp := f.Name()
		defer func() { _ = os.Remove(tmp) }()
		if _, err = f.Write(pending); err == nil {
			err = f.Sync()
		}
		closeErr := f.Close()
		if err != nil {
			return err
		}
		if closeErr != nil {
			return closeErr
		}
		if err := fsutil.Rename(tmp, path); err != nil {
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
	if data, err := os.ReadFile(path); err == nil {
		root := wsp.Root{Workspace: s.workspace, Genesis: digest.Digest(s.cfg.ControlGenesis)}
		repository, err := a.foundingRepository()
		if err != nil {
			return err
		}
		var pending pendingFounding
		if err := json.Unmarshal(data, &pending); err != nil || pending.Root != root || pending.Repository != repository {
			return apperr.New(apperr.CodeUntrusted, "invalid founding authorization", nil)
		}
		if _, err := wsp.VerifyGenesis(s.workspace, pending.Genesis, root.Genesis); err != nil {
			return wspError(err)
		}
		pinned, err := a.trustRoot(s.workspace).Pinned()
		if err != nil {
			return err
		}
		if !s.acceptNewGenesis && pinned != (wsp.Root{}) && pinned != root {
			return wspError(&wsp.TrustRootChangedError{Pinned: pinned, Configured: root})
		}
		repoPin := wsp.Root{}
		if repo := a.repositoryTrustRoot(); repo != nil {
			repoPin, err = repo.Pinned()
			if err != nil {
				return err
			}
		}
		// The durable capability names the exact repository pin that founding
		// was authorized to replace. A matching workspace pin alone is not
		// permission to overwrite a checkout that has since changed roots.
		if !s.acceptNewGenesis && repoPin != root && repoPin != pending.PreviousRepo {
			return wspError(&wsp.TrustRootChangedError{Pinned: repoPin, Configured: root})
		}
		if pinned != root {
			if err := wsp.PublishGenesis(ctx, s.store, pending.Genesis); err != nil {
				return storageError(err)
			}
		}
		recovery = true
		s.founded = !s.acceptNewGenesis && (pinned != root || repoPin != root)
		if s.founded {
			s.foundingRepo = &pending.PreviousRepo
		}
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
	if errors.Is(err, keystore.ErrLocked) {
		return apperr.Wrap(apperr.CodeKeyringLocked, unavailable.Reason, err, nil)
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
	return filepath.Join(a.checkpointDir(), "founding", fmt.Sprintf("%x.json", sum)), nil
}

// pendingFounding is a local authorization, persisted before configuration or
// trust pins change. It is never obtained from untrusted workspace storage.
type pendingFounding struct {
	Root         wsp.Root `json:"root"`
	Repository   string   `json:"repository"`
	PreviousRepo wsp.Root `json:"previous_repo"`
	Genesis      []byte   `json:"genesis"`
}

func (a *App) foundingRepository() (string, error) {
	path, err := config.ProjectConfigPathFrom(a.RepositoryDir)
	if err != nil {
		return "", err
	}
	return filepath.Abs(path)
}
