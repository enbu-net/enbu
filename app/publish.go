package app

import (
	"context"
	"errors"
	"fmt"

	"github.com/enbu-net/enbu/pkg/storage"
	"github.com/enbu-net/enbu/pkg/wsp"
	"github.com/opencontainers/go-digest"
)

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
