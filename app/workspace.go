package app

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"slices"
	"strings"
	"time"

	agecrypto "filippo.io/age"
	"github.com/enbu-net/enbu/pkg/age"
	"github.com/enbu-net/enbu/pkg/apperr"
	"github.com/enbu-net/enbu/pkg/bundle"
	"github.com/enbu-net/enbu/pkg/config"
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
	ids       []agecrypto.Identity
	signer    signing.Signer
}

func (s *session) Close() {
	CloseIdentities(s.ids)
	if s.signer != nil {
		_ = s.signer.Close()
	}
}

func (a *App) checkpoints(workspace, genesis string) *wsp.Checkpoints {
	dir := a.CheckpointDir
	if dir == "" {
		dir = filepath.Join(config.DataDir(), "checkpoints")
	}
	return wsp.OpenCheckpoints(dir, workspace, digest.Digest(genesis))
}

// wspError classifies verification failures so callers can tell an attack or
// rollback from an ordinary failure.
func wspError(err error) error {
	var fork *wsp.ForkError
	switch {
	case err == nil:
		return nil
	case errors.As(err, &fork):
		return apperr.Wrap(apperr.CodeControlForked, "two admins changed the members at the same time; an admin must resolve the fork", err, apperr.Params{"heads": fmt.Sprint(len(fork.Heads))})
	case errors.Is(err, wsp.ErrRollback):
		return apperr.Wrap(apperr.CodeRollback, "storage shows less than this device already accepted", err, nil)
	case errors.Is(err, wsp.ErrInvalid), errors.Is(err, storage.ErrCorrupt):
		return apperr.Wrap(apperr.CodeUntrusted, "stored data failed verification", err, nil)
	default:
		return storageError(err)
	}
}

// openControl verifies the Control DAG without loading any key. It fails with
// CodeControlForked while two heads compete.
func (a *App) openControl(ctx context.Context) (*session, error) {
	s, err := a.openControlView(ctx)
	if err != nil {
		return nil, err
	}
	if s.head == nil {
		return nil, wspError(&wsp.ForkError{Heads: s.view.Heads})
	}
	return s, nil
}

// openControlView is openControl that also returns a forked DAG, so an admin can resolve it.
func (a *App) openControlView(ctx context.Context) (*session, error) {
	cfg, err := a.loadProject()
	if err != nil {
		return nil, err
	}
	store, err := a.workspaceStorage(ctx)
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
	// The checkpoint belongs to this trust root; the genesis may have just been created.
	s.cps = a.checkpoints(s.workspace, s.cfg.ControlGenesis)
	cp, err := s.cps.Control()
	if err != nil {
		return err
	}
	view, err := wsp.LoadControl(ctx, s.store, s.workspace, digest.Digest(s.cfg.ControlGenesis), cp)
	if errors.Is(err, storage.ErrNotFound) {
		return apperr.Wrap(apperr.CodeIncompatibleStorage, "storage has no workspace control; use an empty location", err, nil)
	}
	if err != nil {
		return wspError(err)
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
	s, err := a.openControl(ctx)
	if err != nil {
		return nil, err
	}
	if a.Identities == nil {
		return nil, fmt.Errorf("identity store is not initialized")
	}
	if s.signer, err = a.Identities.LoadSigner(s.workspace); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, apperr.New(apperr.CodeNotInitialized, "no signing key found (run 'enbu init' first)", nil)
		}
		return nil, fmt.Errorf("loading signing key: %w", err)
	}
	if _, ok := s.head.Principal(s.signer.Public().DeviceID()); !ok {
		s.Close()
		return nil, apperr.New(apperr.CodeNotMember, "this device is not approved for the workspace yet", apperr.Params{"fingerprint": s.signer.Public().DeviceID().Fingerprint()})
	}
	if s.ids, err = LoadIdentities(a.Identities, s.workspace); err != nil {
		s.Close()
		return nil, err
	}
	return s, nil
}

func (s *session) self() signing.DeviceID { return s.signer.Public().DeviceID() }

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
func (s *session) loadResource(ctx context.Context, env string, also ...digest.Digest) (*wsp.StateView, error) {
	resource := s.resource(env)
	sv, err := wsp.LoadStates(ctx, s.store, s.view, s.workspace, resource, also...)
	if err != nil {
		return nil, wspError(err)
	}
	if sv.Graph.Len() == 0 {
		return nil, storageError(storage.ErrNotFound)
	}
	if err := s.cps.CheckStates(resource, sv.Graph); err != nil {
		return nil, wspError(err)
	}
	return sv, nil
}

// decrypt reads the ciphertext of one verified revision, checks it is the one
// the signed State names, and decrypts it. This is the only place a revision's
// blob is transferred, so only revisions whose content is used cost anything.
func (s *session) decrypt(ctx context.Context, st *wsp.VerifiedState) (map[string]string, error) {
	ciphertext, err := wsp.ReadCiphertext(ctx, s.store, st)
	if err != nil {
		return nil, wspError(err)
	}
	return decryptSecretsObject(ciphertext, s.ids...)
}

// readResource returns the merged current content of env. The heads must have
// been written by current members, except heads this device already accepted
// (so an admin can take over what a since-removed member last wrote). choices
// settles conflicts a person has already decided. With record set the verified
// view becomes this device's checkpoint.
func (s *session) readResource(ctx context.Context, env string, choices map[string]merge.Choice, record bool, also ...digest.Digest) (*resourceRead, error) {
	sv, err := s.loadResource(ctx, env, also...)
	if err != nil {
		return nil, err
	}
	return s.mergeResource(ctx, env, sv, choices, record)
}

func (s *session) mergeResource(ctx context.Context, env string, sv *wsp.StateView, choices map[string]merge.Choice, record bool) (*resourceRead, error) {
	resource := s.resource(env)
	accepted, err := s.cps.State(resource)
	if err != nil {
		return nil, err
	}
	heads := s.trustedHeads(sv, accepted)
	if len(heads) == 0 {
		return nil, wspError(fmt.Errorf("%w: no revision of %s was written by a current member", wsp.ErrInvalid, resource))
	}
	r := &resourceRead{view: sv, heads: heads}
	maps := make([]map[string]string, len(r.heads))
	for i, h := range r.heads {
		if maps[i], err = s.decrypt(ctx, h); err != nil {
			return nil, err
		}
	}
	if len(maps) == 1 {
		r.secrets = maps[0]
	} else {
		if missing := sv.Graph.Missing(); len(missing) > 0 {
			return nil, wspError(fmt.Errorf("%w: revision %s is missing, so the heads cannot be merged yet", wsp.ErrRollback, missing[0]))
		}
		var bases []map[string]string
		for _, b := range sv.Graph.MergeBases(r.parents()) {
			m, err := s.decrypt(ctx, sv.States[b])
			if err != nil {
				return nil, err
			}
			bases = append(bases, m)
		}
		r.secrets, r.conflicts = merge.Merge(bases, maps, choices)
	}
	if record {
		if err := s.cps.AcceptStates(resource, sv.Graph, r.parents()); err != nil {
			return nil, wspError(err)
		}
	}
	return r, nil
}

// trustedHeads picks the heads this device may read as current. A head must be
// written by a current member, or be one this device accepted while its author
// was a member (so an admin can take over what a since-removed member last
// wrote). A head failing both is not an error, because anyone able to write to
// storage can publish one; it is set aside and its parents stand in for it, so
// it neither injects content nor blocks reading.
func (s *session) trustedHeads(sv *wsp.StateView, accepted []digest.Digest) []*wsp.VerifiedState {
	trusted := func(h *wsp.VerifiedState) bool {
		return wsp.AuthorIsCurrent(s.head, h) == nil || slices.Contains(accepted, h.Digest)
	}
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
// new ciphertext to someone who was removed in the meantime.
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
// revision that merges parents. Storage has no compare-and-swap, so publishing
// never replaces anything: a concurrent writer's revision stays beside this one
// and the next reader merges them.
func (s *session) writeState(ctx context.Context, env string, secrets map[string]string, parents []digest.Digest) (digest.Digest, error) {
	ciphertext, err := age.EncryptForPublicKeys(bundle.Marshal(secrets), s.head.Recipients())
	if err != nil {
		return "", err
	}
	if err := s.controlUnchanged(ctx); err != nil {
		return "", err
	}
	resource := s.resource(env)
	next := wsp.State{Workspace: s.workspace, Resource: resource, Parents: parents, Control: s.head.Digest,
		Ciphertext: digest.FromBytes(ciphertext), Author: s.self(), CreatedAt: time.Now().Unix()}
	blob, err := wsp.SignState(next, s.signer)
	if err != nil {
		return "", err
	}
	rev := digest.FromBytes(blob)
	// Verify what we are about to publish before it becomes public.
	if _, err := wsp.VerifyRevision(s.view, s.workspace, resource, rev, blob); err != nil {
		return "", err
	}
	obj := storage.Object{Kind: storage.KindState, Scope: next.Scope(), Rev: rev, Head: blob, Blobs: [][]byte{ciphertext}}
	if err := s.store.Publish(ctx, obj); err != nil {
		return "", fmt.Errorf("saving encrypted secrets: %w", storageError(err))
	}
	// Members may have changed while we were publishing. The revision stays, and
	// the caller publishes again for the new recipient set on top of it.
	if err := s.controlUnchanged(ctx); err != nil {
		return rev, err
	}
	return rev, nil
}

// acceptPublished records the view that includes a revision just published, so
// a later view without it is a rollback.
func (s *session) acceptPublished(ctx context.Context, env string, rev digest.Digest) error {
	sv, err := wsp.LoadStates(ctx, s.store, s.view, s.workspace, s.resource(env), rev)
	if err != nil {
		return wspError(err)
	}
	accepted, err := s.cps.State(s.resource(env))
	if err != nil {
		return err
	}
	heads := s.trustedHeads(sv, accepted)
	digests := make([]digest.Digest, len(heads))
	for i, h := range heads {
		digests[i] = h.Digest
	}
	return wspError(s.cps.AcceptStates(s.resource(env), sv.Graph, digests))
}
