package app

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"

	"github.com/enbu-net/enbu/pkg/apperr"
	"github.com/enbu-net/enbu/pkg/config"
	"github.com/enbu-net/enbu/pkg/identity"
	"github.com/enbu-net/enbu/pkg/signing"
	"github.com/enbu-net/enbu/pkg/storage"
	"github.com/enbu-net/enbu/pkg/wsp"
	"github.com/opencontainers/go-digest"
)

// session is a workspace opened for use: its Control DAG has been verified
// against the trusted genesis and the local checkpoint, so everything derived
// from it (principals, recipients) is authoritative. Nothing read from storage
// outside this verification is trusted.
type session struct {
	app       *App
	store     storage.Store
	cfg       *config.ProjectConfig
	workspace string
	view      *wsp.ControlView
	head      *wsp.Verified // the only head; nil while the Control is forked
	cps       *wsp.Checkpoints
	id        identity.Identity
	signer    signing.Signer
	// acceptNewGenesis replaces a different pinned trust root instead of failing.
	acceptNewGenesis bool
	// founded is set when this device founded the workspace and has not pinned
	// it yet, which moves the repository pin to it.
	founded bool
	// diagnostic verifies the existing trust state without pinning or accepting it.
	diagnostic bool
	// replaced is the root that acceptNewGenesis replaced, or a zero Root.
	replaced wsp.Root
}

func (s *session) Close() {
	if s.id != nil {
		_ = s.id.Close()
	}
	if s.signer != nil {
		_ = s.signer.Close()
	}
}

func (a *App) checkpointDir() string {
	if a.CheckpointDir != "" {
		return a.CheckpointDir
	}
	return filepath.Join(config.DataDir(), "checkpoints")
}

func (a *App) checkpoints(workspace, genesis string) *wsp.Checkpoints {
	return wsp.OpenCheckpoints(a.checkpointDir(), workspace, digest.Digest(genesis), a.clock())
}

// trust holds the roots this device pinned on first use, per workspace and
// per repository.
func (a *App) trust() *wsp.Trust {
	return wsp.OpenTrust(a.checkpointDir(), a.clock())
}

// repositoryKey is the absolute path of the repository's enbu.toml, which
// keys its pin, or "" when the path is unknown.
func (a *App) repositoryKey() string {
	path, err := config.ProjectConfigPathFrom(a.RepositoryDir)
	if err != nil {
		return ""
	}
	if abs, err := filepath.Abs(path); err == nil {
		path = abs
	}
	return path
}

// wspError classifies verification failures so callers can tell an attack or
// rollback from an ordinary failure.
func wspError(err error) error {
	var fork *wsp.ForkError
	var changed *wsp.TrustRootChangedError
	switch {
	case err == nil:
		return nil
	case errors.As(err, &changed):
		configured := string(changed.Configured.Genesis)
		if configured == "" {
			configured = "missing"
		}
		return apperr.Wrap(apperr.CodeTrustRootChanged,
			fmt.Sprintf("enbu.toml names workspace %s with control_genesis %s, but this device trusts workspace %s with %s; "+
				"unless an admin confirms out of band that they re-created the workspace, do not continue. "+
				"After confirming, run 'enbu init --accept-new-genesis'",
				changed.Configured.Workspace, configured, changed.Pinned.Workspace, changed.Pinned.Genesis),
			err, apperr.Params{"pinned": string(changed.Pinned.Genesis), "configured": configured,
				"pinned_workspace": changed.Pinned.Workspace, "configured_workspace": changed.Configured.Workspace})
	case errors.As(err, &fork):
		return apperr.Wrap(apperr.CodeControlForked, "two admins changed the members at the same time; it is resolved when an admin of both changes opens enbu", err, apperr.Params{"heads": fmt.Sprint(len(fork.Heads))})
	case errors.Is(err, wsp.ErrRollback):
		return apperr.Wrap(apperr.CodeRollback, "storage shows less than this device already accepted", err, nil)
	case errors.Is(err, wsp.ErrInvalid), errors.Is(err, storage.ErrCorrupt):
		return apperr.Wrap(apperr.CodeUntrusted, "stored data failed verification", err, nil)
	default:
		return storageError(err)
	}
}

// openControl verifies the Control DAG. When two admins changed the members at
// the same time and this device is an admin of every head, it joins the heads
// with a 3-way merge first; any other device fails with CodeControlForked until
// an admin does.
func (a *App) openControl(ctx context.Context) (*session, error) {
	cfg, err := a.loadProject()
	if err != nil {
		return nil, err
	}
	return a.openControlWith(ctx, cfg)
}

// openControlWith is openControl on an enbu.toml already loaded.
func (a *App) openControlWith(ctx context.Context, cfg *config.ProjectConfig) (*session, error) {
	for attempt := 0; ; attempt++ {
		s, err := a.openControlViewWith(ctx, cfg)
		if err != nil {
			return nil, err
		}
		if s.head != nil {
			return s, nil
		}
		resolved := false
		if attempt < forkRetries {
			if resolved, err = a.resolveFork(ctx, s); err != nil {
				return nil, err
			}
		}
		if !resolved {
			return nil, wspError(&wsp.ForkError{Heads: s.view.Heads})
		}
	}
}

// forkRetries bounds how often openControl joins a fork again, which happens
// when two admins join the same fork at once.
const forkRetries = 3

// resolveFork publishes the 3-way merge of the competing heads (see
// wsp.MergePrincipals). It reports false, publishing nothing, when this device
// is not an admin of every head.
func (a *App) resolveFork(ctx context.Context, s *session) (bool, error) {
	if a.Identities == nil {
		return false, nil
	}
	d, err := a.Identities.Load(s.workspace)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil // a device without keys cannot join the heads; it reports the fork
	}
	if err != nil {
		return false, identityError(fmt.Errorf("loading identity: %w", err))
	}
	defer func() { _ = d.Close() }()
	signer := d.Signer
	author := signer.Public().DeviceID()
	for _, h := range s.view.Heads {
		if p, ok := h.Principal(author); !ok || !p.Admin {
			return false, nil
		}
	}
	v, err := wsp.ResolveFork(ctx, s.store, s.view, signer)
	var fork *wsp.ForkError
	if errors.As(err, &fork) {
		return true, nil // another admin joined it at the same time; join again
	}
	if err != nil {
		return false, wspError(err)
	}
	if err := a.acceptControlHead(ctx, v); err != nil {
		return false, err
	}
	// The resolution may have dropped members the existing ciphertext is still
	// encrypted for, so it re-encrypts exactly as a removal does. A failure
	// fails the operation that joined, even a read: the join is published and
	// is not retried, so this is the only moment that tells the admin to sync.
	if err := a.reencryptAll(ctx); err != nil {
		return false, apperr.Wrap(apperr.CodeReencryptIncomplete, "member changes were joined but re-encryption is incomplete; run 'enbu sync' for each environment", err, nil)
	}
	return true, nil
}

// openControlView verifies the Control DAG without loading any key and also
// returns a forked DAG.
func (a *App) openControlView(ctx context.Context) (*session, error) {
	cfg, err := a.loadProject()
	if err != nil {
		return nil, err
	}
	return a.openControlViewWith(ctx, cfg)
}

func (a *App) openControlViewWith(ctx context.Context, cfg *config.ProjectConfig) (*session, error) {
	store, err := a.workspaceStorage(ctx, cfg)
	if err != nil {
		return nil, err
	}
	s := &session{app: a, store: store, cfg: cfg, workspace: cfg.WorkspaceID}
	if err := a.verifyControl(ctx, s); err != nil {
		return nil, err
	}
	return s, nil
}

func (a *App) verifyControl(ctx context.Context, s *session) error {
	if s.cfg.ControlGenesis == "" {
		return apperr.New(apperr.CodeInvalidArgument, "enbu.toml has no control_genesis; use the enbu.toml shared by an admin and run enbu init", nil)
	}
	genesis := digest.Digest(s.cfg.ControlGenesis)
	// enbu.toml travels through Git, so whoever can change it could name a
	// workspace and genesis they founded. This device keeps trusting the first
	// root it saw, both for the workspace ID and for this repository's
	// enbu.toml, since a commit can change the workspace ID too.
	root := wsp.Root{Workspace: s.workspace, Genesis: genesis}
	trust, repo := a.trust(), a.repositoryKey()
	mode := wsp.PinFirst
	switch {
	case s.acceptNewGenesis:
		mode = wsp.PinReplace
	case s.founded:
		mode = wsp.PinFounded
	}
	if err := trust.Check(root, repo, mode); err != nil {
		return wspError(err)
	}
	// The checkpoint belongs to this trust root; the genesis may have just been created.
	s.cps = a.checkpoints(s.workspace, s.cfg.ControlGenesis)
	cp, err := s.cps.Control()
	if err != nil {
		return err
	}
	view, err := wsp.LoadControl(ctx, s.store, s.workspace, genesis, cp)
	if errors.Is(err, storage.ErrNotFound) {
		return apperr.Wrap(apperr.CodeIncompatibleStorage, "storage has no workspace control; use an empty location", err, nil)
	}
	if err != nil {
		return wspError(err)
	}
	if s.diagnostic {
		s.view, s.head = view, nil
		if !view.Forked() {
			s.head = view.Heads[0]
		}
		return nil
	}
	// Pin only a genesis that verified, so a typo or an unreachable storage
	// never becomes the trust root.
	previous, err := trust.Pin(root, repo, mode)
	if err != nil {
		return wspError(err)
	}
	if mode == wsp.PinReplace {
		s.replaced = previous
	}
	if err := s.cps.AcceptControl(view); err != nil {
		return wspError(err)
	}
	s.view, s.head = view, nil
	if !view.Forked() {
		s.head = view.Heads[0]
	}
	return nil
}

// openSession also loads the encryption identity and the signing key, and
// requires this device to be a principal of the verified Control.
func (a *App) openSession(ctx context.Context) (*session, error) {
	cfg, err := a.loadProject()
	if err != nil {
		return nil, err
	}
	return a.openSessionWith(ctx, cfg)
}

// openEnvironment resolves env from enbu.toml before opening a session on the
// same config, so an unknown environment is reported from the local file
// before storage is reached or membership is checked.
func (a *App) openEnvironment(ctx context.Context, env string) (*session, *ResolvedEnvironment, error) {
	cfg, err := a.loadProject()
	if err != nil {
		return nil, nil, err
	}
	resolved, err := resolveEnvironment(func() (*config.ProjectConfig, error) { return cfg, nil }, env)
	if err != nil {
		return nil, nil, err
	}
	s, err := a.openSessionWith(ctx, cfg)
	if err != nil {
		return nil, nil, err
	}
	return s, resolved, nil
}

func (a *App) openSessionWith(ctx context.Context, cfg *config.ProjectConfig) (*session, error) {
	s, err := a.openControlWith(ctx, cfg)
	if err != nil {
		return nil, err
	}
	d, err := loadDevice(a.Identities, s.workspace)
	if err != nil {
		return nil, err
	}
	s.id, s.signer = d.Identity, d.Signer
	if _, ok := s.head.Principal(s.self()); !ok {
		s.Close()
		return nil, apperr.New(apperr.CodeNotMember, "this device is not approved for the workspace yet", apperr.Params{"fingerprint": s.self().Fingerprint()})
	}
	return s, nil
}

func (s *session) self() signing.DeviceID { return s.signer.Public().DeviceID() }

func (s *session) resource(env string) string { return s.cfg.Resource(env) }
