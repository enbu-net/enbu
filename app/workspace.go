package app

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"

	agecrypto "filippo.io/age"
	"github.com/enbu-net/enbu/pkg/age"
	"github.com/enbu-net/enbu/pkg/apperr"
	"github.com/enbu-net/enbu/pkg/bundle"
	"github.com/enbu-net/enbu/pkg/config"
	"github.com/enbu-net/enbu/pkg/signing"
	"github.com/enbu-net/enbu/pkg/storage"
	"github.com/enbu-net/enbu/pkg/wsp"
	"github.com/opencontainers/go-digest"
)

// session is a workspace opened for use: its Control chain has been verified
// against the trusted genesis and the local checkpoint, so everything derived
// from it (principals, recipients) is authoritative. Nothing read from storage
// outside this verification is trusted.
type session struct {
	app       *App
	store     *storage.Store
	cfg       *config.ProjectConfig
	workspace string
	head      *wsp.Head
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
	switch {
	case err == nil:
		return nil
	case errors.Is(err, wsp.ErrRollback):
		return apperr.Wrap(apperr.CodeRollback, "storage returned data older than this device already accepted", err, nil)
	case errors.Is(err, wsp.ErrInvalid), errors.Is(err, storage.ErrDigestMismatch):
		return apperr.Wrap(apperr.CodeUntrusted, "stored data failed verification", err, nil)
	default:
		return storageError(err)
	}
}

// openControl verifies the Control chain without loading any key.
func (a *App) openControl(ctx context.Context) (*session, error) {
	cfg, err := a.loadProject()
	if err != nil {
		return nil, err
	}
	store, err := a.workspaceStorage(ctx)
	if err != nil {
		return nil, err
	}
	s := &session{app: a, store: store, cfg: cfg, workspace: cfg.WorkspaceID}
	s.head, err = a.verifyControl(ctx, s)
	if err != nil {
		return nil, err
	}
	return s, nil
}

func (a *App) verifyControl(ctx context.Context, s *session) (*wsp.Head, error) {
	if s.cfg.ControlGenesis == "" {
		return nil, apperr.New(apperr.CodeInvalidArgument, "enbu.toml has no control_genesis; use the enbu.toml shared by an admin and run enbu init", nil)
	}
	// The checkpoint belongs to this trust root; the genesis may have just been created.
	s.cps = a.checkpoints(s.workspace, s.cfg.ControlGenesis)
	cp, err := s.cps.Control()
	if err != nil {
		return nil, err
	}
	head, err := wsp.LoadControl(ctx, s.store, s.workspace, digest.Digest(s.cfg.ControlGenesis), cp)
	if errors.Is(err, storage.ErrNotFound) {
		return nil, apperr.Wrap(apperr.CodeIncompatibleStorage, "storage has no workspace control; use an empty location", err, nil)
	}
	if err != nil {
		return nil, wspError(err)
	}
	if err := s.cps.AcceptControl(head.Verified); err != nil {
		return nil, wspError(err)
	}
	return head, nil
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

func secretsResource(env string) string {
	if env == "" {
		env = DefaultEnvironment
	}
	return "secrets/" + env
}

type stateRead struct {
	state   *wsp.VerifiedState
	secrets map[string]string
	version storage.Version
}

// readState loads and verifies the SignedState a ref names, then decrypts its
// ciphertext. With current set the state must not be older than what this
// device accepted, and is recorded as accepted; history snapshots are older by
// design and skip that check.
//
// The checkpoint is shared by every enbu process of this device. Another
// process (the GUI, a script) can publish and accept a newer state between
// this one fetching the ref and comparing the state with the checkpoint. That
// is not storage rolling back, so on a mismatch the ref is fetched again and
// only a storage that keeps serving the same old state is reported.
func (s *session) readState(ctx context.Context, ref, env string, current bool) (*stateRead, error) {
	var last digest.Digest
	for attempt := 0; ; attempt++ {
		d, version, err := s.store.Refs.Get(ctx, ref)
		if err != nil {
			return nil, storageError(err)
		}
		read, err := s.readStateAt(ctx, ref, env, d, version, current)
		if !current || !errors.Is(err, wsp.ErrRollback) || d == last || attempt >= maxSiblingRetries {
			return read, err
		}
		last = d // storage moved on since the fetch that looked old; look again
	}
}

// maxSiblingRetries bounds how often a read follows a ref that keeps moving
// under it before giving up.
const maxSiblingRetries = 3

func (s *session) readStateAt(ctx context.Context, ref, env string, d digest.Digest, version storage.Version, current bool) (*stateRead, error) {
	blob, err := s.readBlob(ctx, ref, d)
	if err != nil {
		return nil, err
	}
	var st *wsp.VerifiedState
	if current {
		// The current state must have been written by someone who is a member now.
		if st, err = s.verifyCurrent(ctx, env, blob); err != nil {
			return nil, err
		}
		if err := s.cps.CheckState(st); err != nil {
			return nil, wspError(err)
		}
	} else if st, err = s.verifyHistorical(ctx, env, blob); err != nil {
		return nil, err
	}
	ciphertext, err := s.readBlob(ctx, ref, st.Ciphertext)
	if err != nil {
		return nil, err
	}
	secrets, err := decryptSecretsObject(ciphertext, s.ids...)
	if err != nil {
		return nil, err
	}
	if current {
		if err := s.cps.AcceptState(st); err != nil {
			return nil, wspError(err)
		}
	}
	return &stateRead{state: st, secrets: secrets, version: version}, nil
}

// verifyCurrent verifies the state a ref names as the current one. Its author
// must be a member now, with one exception: a state this device itself
// accepted while its author was a member stays acceptable after the author is
// removed, otherwise an admin could not take over what that member last wrote.
// The exception is by digest, so a state the removed member signs after the
// removal is not covered by it.
func (s *session) verifyCurrent(ctx context.Context, env string, blob []byte) (*wsp.VerifiedState, error) {
	st, err := wsp.VerifyState(s.head.Verified, s.workspace, secretsResource(env), blob)
	if err == nil {
		return st, nil
	}
	cp, cerr := s.cps.State(secretsResource(env))
	if cerr == nil && cp != nil && cp.Digest == digest.FromBytes(blob) {
		return s.verifyHistorical(ctx, env, blob)
	}
	return nil, wspError(err)
}

// verifyHistorical judges an older state, such as a history snapshot, by the
// Control it was written under. Someone who was a member then and has since
// been removed signed it validly, so the current member list is the wrong judge.
func (s *session) verifyHistorical(ctx context.Context, env string, blob []byte) (*wsp.VerifiedState, error) {
	generation, d, err := wsp.StateControl(blob)
	if err != nil {
		return nil, wspError(err)
	}
	written, err := wsp.ControlAt(ctx, s.store, s.head.Verified, generation, d)
	if err != nil {
		return nil, wspError(err)
	}
	st, err := wsp.VerifyHistoricalState(written, s.workspace, secretsResource(env), blob)
	if err != nil {
		return nil, wspError(err)
	}
	return st, nil
}

func (s *session) readBlob(ctx context.Context, ref string, d digest.Digest) ([]byte, error) {
	data, err := readBlob(ctx, s.store, d)
	if errors.Is(err, storage.ErrNotFound) {
		// A missing blob behind an existing ref is corruption, not an absent ref.
		return nil, fmt.Errorf("ref %s points to missing blob %s", ref, d)
	}
	if err != nil {
		return nil, wspError(err)
	}
	return data, nil
}

// writeState encrypts secrets for the verified recipient set, signs a State
// for it and points ref at that State. cur is the state being replaced.
// errControlMoved means the member list changed after the session verified it.
// Nothing has been published; the caller reopens the session and tries again.
var errControlMoved = errors.New("workspace members changed while writing")

// controlUnchanged re-reads the control head just before anything is
// published. Encrypting for a recipient set that has since changed would hand
// new ciphertext to someone who was removed in the meantime.
func (s *session) controlUnchanged(ctx context.Context) error {
	d, _, err := s.store.Refs.Get(ctx, wsp.ControlRef)
	if err != nil {
		return storageError(err)
	}
	if d != s.head.Digest {
		return errControlMoved
	}
	return nil
}

func (s *session) writeState(ctx context.Context, ref, env string, secrets map[string]string, cur *stateRead, expected storage.Version) (digest.Digest, error) {
	ciphertext, err := age.EncryptForPublicKeys(bundle.Marshal(secrets), s.head.Recipients())
	if err != nil {
		return "", err
	}
	if err := s.controlUnchanged(ctx); err != nil {
		return "", err
	}
	ct, err := s.store.Blobs.Put(ctx, bytes.NewReader(ciphertext))
	if err != nil {
		return "", fmt.Errorf("saving encrypted secrets: %w", storageError(err))
	}
	next := wsp.State{Workspace: s.workspace, Resource: secretsResource(env), Sequence: 1,
		ControlGeneration: s.head.Generation, Control: s.head.Digest, Ciphertext: ct, Author: s.self()}
	if cur != nil {
		next.Sequence, next.Previous = cur.state.Sequence+1, cur.state.Digest
	}
	blob, err := wsp.SignState(next, s.signer)
	if err != nil {
		return "", err
	}
	// Verify what we are about to publish, and check it against the checkpoint,
	// before the ref moves: once it has moved the state is public, so a failure
	// found afterwards would leave a published state this device refuses.
	st, err := wsp.VerifyState(s.head.Verified, s.workspace, next.Resource, blob)
	if err != nil {
		return "", err
	}
	if err := s.cps.CheckState(st); err != nil {
		// Another process of this device may have published and accepted a
		// state at this sequence since the read: then the ref has moved and the
		// caller should retry on it, like any lost race. Only a ref that still
		// names what was read is storage disagreeing with the checkpoint.
		if moved, lookErr := s.refMoved(ctx, ref, cur); lookErr == nil && moved {
			return "", apperr.Wrap(apperr.CodeConflict, "another update landed first", storage.ErrConflict, nil)
		}
		return "", wspError(err)
	}
	stateDigest, err := s.store.Blobs.Put(ctx, bytes.NewReader(blob))
	if err != nil {
		return "", fmt.Errorf("saving signed state: %w", storageError(err))
	}
	if err := storageError(s.store.Refs.Put(ctx, ref, stateDigest, expected)); err != nil {
		return "", err
	}
	// Some backends (OCI) cannot make the ref update atomic, so another writer's
	// update can land on top of ours. Look once more: if the ref no longer names
	// our state we lost, and the caller retries from what is there now instead
	// of recording a state nobody will read.
	// A newer ref that descends from our state is not a loss: another process
	// read what we published and built on it, so the update is in storage.
	if now, _, err := s.store.Refs.Get(ctx, ref); err != nil {
		return "", storageError(err)
	} else if now != stateDigest {
		if descends, err := s.descendsFrom(ctx, ref, env, now, st); err != nil || !descends {
			cause := storage.ErrConflict
			if err != nil {
				cause = fmt.Errorf("%w: %w", storage.ErrConflict, err)
			}
			return "", apperr.Wrap(apperr.CodeConflict, "another update replaced this one", cause, nil)
		}
		// The checkpoint already names the newer state (or will, when that
		// process records it); ours needs no record of its own.
		return stateDigest, nil
	}
	if err := s.cps.AcceptState(st); err != nil {
		return "", wspError(err)
	}
	return stateDigest, nil
}

// refMoved reports whether ref no longer names the state a write started from.
func (s *session) refMoved(ctx context.Context, ref string, cur *stateRead) (bool, error) {
	now, _, err := s.store.Refs.Get(ctx, ref)
	if errors.Is(err, storage.ErrNotFound) {
		return cur != nil, nil
	}
	if err != nil {
		return false, err
	}
	return cur == nil || now != cur.state.Digest, nil
}

// descendsFrom reports whether the state named head has ours among its
// ancestors, following Previous links while the sequence stays above ours.
func (s *session) descendsFrom(ctx context.Context, ref, env string, head digest.Digest, ours *wsp.VerifiedState) (bool, error) {
	d := head
	for range maxSiblingRetries + 1 {
		if d == ours.Digest {
			return true, nil
		}
		blob, err := s.readBlob(ctx, ref, d)
		if err != nil {
			return false, err
		}
		st, err := s.verifyHistorical(ctx, env, blob)
		if err != nil {
			return false, err
		}
		if st.Sequence <= ours.Sequence || st.Previous == "" {
			return false, nil
		}
		d = st.Previous
	}
	return false, nil
}
