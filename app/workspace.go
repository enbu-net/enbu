package app

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strings"

	agecrypto "filippo.io/age"
	"github.com/enbu-net/enbu/pkg/apperr"
	"github.com/enbu-net/enbu/pkg/config"
	"github.com/enbu-net/enbu/pkg/identity"
	"github.com/enbu-net/enbu/pkg/merge"
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
	// removing is a member a removal is about to drop: what this session
	// writes is encrypted without it, under the Control that still lists it.
	removing signing.DeviceID
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
// first; any other device fails with CodeControlForked until an admin does.
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

// resolveFork publishes a Control that keeps only the principals every head
// lists and the admin rights every head grants, so a fork grants nothing by
// chance. It reports false, publishing nothing, when this device is not an
// admin of every head.
func (a *App) resolveFork(ctx context.Context, s *session) (bool, error) {
	d, err := loadDevice(a.Identities, s.workspace)
	if err != nil {
		return false, nil // a device without its keys cannot join the heads; it reports the fork
	}
	defer func() { _ = d.Close() }()
	author := d.Signer.Public().DeviceID()
	for _, h := range s.view.Heads {
		if p, ok := h.Principal(author); !ok || !p.Admin {
			return false, nil
		}
	}
	v, err := wsp.ResolveFork(ctx, s.store, s.view, d.Signer, func(c *wsp.Control) error {
		kept := c.Principals[:0:0]
		for _, p := range c.Principals {
			inAll, adminInAll := true, true
			for _, h := range s.view.Heads {
				q, ok := h.Principal(p.ID)
				inAll = inAll && ok
				adminInAll = adminInAll && ok && q.Admin
			}
			if inAll {
				p.Admin = adminInAll
				kept = append(kept, p)
			}
		}
		c.Principals = kept
		return nil
	})
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
	// encrypted for, so it re-encrypts exactly as a removal does.
	if err := a.reencryptAll(ctx, ""); err != nil {
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

// recipients is the recipient set a revision is encrypted for: the current
// Control's, without the member a removal is about to drop.
func (s *session) recipients() []string {
	var out []string
	for _, p := range s.head.Principals {
		if p.ID != s.removing {
			out = append(out, p.Recipient)
		}
	}
	return out
}

func (s *session) resource(env string) string { return s.cfg.Resource(env) }

// resourceRead is the current content of one environment: every head storage
// shows, decrypted and merged against their merge base. A key the heads changed
// differently is a conflict and is absent from secrets until a person chooses.
type resourceRead struct {
	view      *wsp.StateView
	heads     []*wsp.VerifiedState
	secrets   map[string]string
	conflicts []merge.Conflict
}

func (r *resourceRead) parents() []digest.Digest {
	out := make([]digest.Digest, len(r.heads))
	for i, h := range r.heads {
		out[i] = h.Digest
	}
	return out
}

// loadResource verifies every revision of env that storage shows and checks it
// against what this device accepted before. It decrypts nothing.
func (s *session) loadResource(ctx context.Context, resource string, also ...digest.Digest) (*wsp.StateView, error) {
	for attempt := 0; ; attempt++ {
		sv, err := wsp.LoadStates(ctx, s.store, s.view, s.workspace, resource, also...)
		if err != nil {
			return nil, wspError(err)
		}
		err = s.cps.CheckState(resource, sv)
		if err == nil && sv.Graph.Len() == 0 {
			return nil, storageError(storage.ErrNotFound)
		}
		if err == nil {
			return sv, nil
		}
		// Another process of this device may have accepted a revision after
		// the listing above was taken; a fresh listing shows it. One that
		// storage really lost is still missing, and that stays a rollback.
		if !errors.Is(err, wsp.ErrRollback) || attempt == acceptedRetries {
			return nil, wspError(err)
		}
	}
}

// acceptedRetries bounds how often loadResource reads storage again for
// revisions that other processes of this device accepted meanwhile.
const acceptedRetries = 2

// decrypt reads the ciphertext of one verified revision, checks it is the one
// the signed State names, and decrypts it. This is the only place a revision's
// blob is transferred, so only revisions whose content is used cost anything.
func (s *session) decrypt(ctx context.Context, st *wsp.VerifiedState) (map[string]string, error) {
	ciphertext, err := wsp.ReadCiphertext(ctx, s.store, st)
	// A signed state exists, so a missing blob is lost data, never an empty
	// environment. Treating it as not-found lets mutations replace its secrets.
	if errors.Is(err, storage.ErrNotFound) {
		return nil, wspError(fmt.Errorf("%w: ciphertext for %s is missing: %w", wsp.ErrRollback, st.Digest, err))
	}
	if err != nil {
		return nil, wspError(err)
	}
	return decryptSecretsObject(ciphertext, s.id)
}

// readResource returns the merged current content of env. The heads must have
// been written by current members. choices settles conflicts a person has
// already decided. With record set the Generation of the heads read becomes
// this device's checkpoint.
func (s *session) readResource(ctx context.Context, resource string, choices map[string]merge.Choice, record bool, also ...digest.Digest) (*resourceRead, error) {
	for attempt := 0; ; attempt++ {
		sv, err := s.loadResource(ctx, resource, also...)
		if err != nil {
			return nil, err
		}
		r, err := s.mergeResource(ctx, resource, sv, choices)
		if err == nil && record {
			if err = s.cps.AcceptState(resource, sv, wsp.TopGeneration(r.heads)); err != nil {
				err = wspError(err)
			}
		}
		// Storage changed while this read was working: another process of this
		// device accepted a newer revision, or a compaction deleted a revision
		// this read was about to decrypt. A fresh read sees the new view; a
		// revision storage really lost is still missing then.
		if errors.Is(err, wsp.ErrRollback) && attempt < acceptedRetries {
			continue
		}
		if err != nil {
			return nil, err
		}
		return r, nil
	}
}

func (s *session) mergeResource(ctx context.Context, resource string, sv *wsp.StateView, choices map[string]merge.Choice) (*resourceRead, error) {
	heads := s.trustedHeads(sv)
	if len(heads) == 0 {
		return nil, wspError(fmt.Errorf("%w: no revision of %s was written by a current member", wsp.ErrInvalid, resource))
	}
	r := &resourceRead{view: sv, heads: heads}
	maps := make([]map[string]string, len(r.heads))
	for i, h := range r.heads {
		var err error
		if maps[i], err = s.decrypt(ctx, h); err != nil {
			return nil, err
		}
	}
	if len(maps) == 1 {
		r.secrets = maps[0]
	} else {
		var bases []map[string]string
		found := sv.Graph.MergeBases(r.parents())
		if len(found) == 0 && len(sv.Graph.Missing()) > 0 {
			// The heads share no history storage still holds, because old
			// revisions were deleted. Every head counts as a possible base, so
			// any value they disagree on stays a conflict.
			bases = append(bases, maps...)
		}
		for _, b := range found {
			m, err := s.decrypt(ctx, sv.States[b])
			var noMatch *agecrypto.NoIdentityMatchError
			if errors.As(err, &noMatch) {
				// A new member can read current heads without having the key
				// for their pre-join base. Requiring agreement against every
				// head as a possible base preserves all differing values as
				// conflicts; an empty base could silently lose a deletion.
				bases = append(bases, maps...)
				continue
			}
			if err != nil {
				return nil, err
			}
			bases = append(bases, m)
		}
		r.secrets, r.conflicts = merge.Merge(bases, maps, choices)
	}
	return r, nil
}

// trustedHeads picks the heads this device may read as current: written by a
// current member who was not removed since the Control the head names. A head
// failing that is not an error, because anyone able to write to storage can
// publish one; it is set aside and its parents stand in for it, so it neither
// injects content nor blocks reading.
func (s *session) trustedHeads(sv *wsp.StateView) []*wsp.VerifiedState {
	trusted := func(h *wsp.VerifiedState) bool { return wsp.AuthorIsCurrent(s.view, s.head, h) == nil }
	var heads []*wsp.VerifiedState
	seen := map[digest.Digest]bool{}
	queue := slices.Clone(sv.Heads)
	for len(queue) > 0 {
		h := queue[0]
		queue = queue[1:]
		if seen[h.Digest] {
			continue
		}
		seen[h.Digest] = true
		if trusted(h) {
			heads = append(heads, h)
			continue
		}
		for _, p := range h.Parents {
			if parent, ok := sv.States[p]; ok {
				queue = append(queue, parent)
			}
		}
	}
	// A parent that stands in for a set-aside head may already be covered by another head.
	var out []*wsp.VerifiedState
	for _, h := range heads {
		covered := false
		for _, other := range heads {
			if other.Digest != h.Digest && sv.Graph.Ancestors(other.Digest)[h.Digest] {
				covered = true
				break
			}
		}
		if !covered {
			out = append(out, h)
		}
	}
	slices.SortFunc(out, func(a, b *wsp.VerifiedState) int { return strings.Compare(string(a.Digest), string(b.Digest)) })
	return out
}

// errControlMoved means the member list changed after the session verified it.
// Nothing has been published; the caller reopens the session and tries again.
var errControlMoved = errors.New("workspace members changed while writing")

// controlUnchanged loads the Control DAG again just before and after
// publishing. Encrypting for a recipient set that has since changed would hand
// new ciphertext to someone who was removed in the meantime, and leave a head
// that someone approved in the meantime cannot read.
func (s *session) controlUnchanged(ctx context.Context) error {
	view, err := wsp.LoadControl(ctx, s.store, s.workspace, digest.Digest(s.cfg.ControlGenesis), nil)
	if err != nil {
		return wspError(err)
	}
	if view.Forked() || view.Heads[0].Digest != s.head.Digest {
		return errControlMoved
	}
	return nil
}

// writeState encrypts secrets for the verified recipient set and publishes a
// revision that merges parents, the heads it read. Storage has no compare-and-swap, so publishing
// never replaces anything: a concurrent writer's revision stays beside this one
// and the next reader merges them. The revision is returned once it is
// published, even when the error says members changed meanwhile.
func (s *session) writeState(ctx context.Context, resource, op string, secrets map[string]string, parents []*wsp.VerifiedState) (*wsp.VerifiedState, error) {
	ciphertext, err := s.app.encrypt(encodeSecrets(secrets), s.recipients())
	if err != nil {
		return nil, err
	}
	if err := s.controlUnchanged(ctx); err != nil {
		return nil, err
	}
	parentDigests := make([]digest.Digest, len(parents))
	for i, p := range parents {
		parentDigests[i] = p.Digest
	}
	next := wsp.State{Workspace: s.workspace, Resource: resource, Parents: parentDigests, Generation: wsp.NextGeneration(parents),
		Op: op, Control: s.head.Digest, Ciphertext: digest.FromBytes(ciphertext), Author: s.self(), CreatedAt: s.app.now().Unix()}
	blob, err := wsp.SignState(next, s.signer)
	if err != nil {
		return nil, err
	}
	rev := digest.FromBytes(blob)
	// Verify what we are about to publish before it becomes public.
	st, err := wsp.VerifyRevision(s.view, s.workspace, resource, rev, blob)
	if err != nil {
		return nil, err
	}
	obj := storage.Object{Kind: storage.KindState, Scope: next.Scope(), Rev: rev, Head: blob, Payload: ciphertext}
	if err := s.store.Publish(ctx, obj); err != nil {
		return nil, fmt.Errorf("saving encrypted secrets: %w", storageError(err))
	}
	// Members may have changed while we were publishing. The revision stays, and
	// the caller publishes again for the new recipient set on top of it.
	if err := s.controlUnchanged(ctx); err != nil {
		return st, err
	}
	return st, nil
}

// acceptPublished checks storage again before advancing the checkpoint: a
// revision accepted before publishing must not disappear during the write.
func (s *session) acceptPublished(ctx context.Context, resource string, st *wsp.VerifiedState) error {
	for attempt := 0; ; attempt++ {
		sv, err := s.loadResource(ctx, resource, st.Digest)
		if err != nil {
			return err
		}
		err = s.acceptView(resource, sv)
		if !errors.Is(err, wsp.ErrRollback) || attempt == acceptedRetries {
			return wspError(err)
		}
	}
}

func (s *session) acceptView(resource string, sv *wsp.StateView) error {
	return s.cps.AcceptState(resource, sv, wsp.TopGeneration(s.trustedHeads(sv)))
}
