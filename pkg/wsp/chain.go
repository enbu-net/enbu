package wsp

import (
	"context"
	"errors"
	"fmt"

	"github.com/enbu-net/enbu/pkg/signing"
	"github.com/enbu-net/enbu/pkg/storage"
	"github.com/opencontainers/go-digest"
)

// maxControls bounds how many Controls one load reads, and maxControlBytes how
// many bytes it reads in total. Both are variables so tests can lower them.
var (
	maxControls     = 10000
	maxControlBytes = 32 << 20
)

// ErrControlFork marks a Control DAG with more than one head. Nothing proceeds
// until an admin publishes a resolution Control.
var ErrControlFork = errors.New("workspace control forked")

// ForkError carries the competing heads so an admin can resolve them.
type ForkError struct{ Heads []*Verified }

func (e *ForkError) Error() string {
	return fmt.Sprintf("%v: %d competing heads; an admin must resolve the fork", ErrControlFork, len(e.Heads))
}

func (e *ForkError) Is(target error) bool { return target == ErrControlFork }

// ControlView is the verified Control DAG as storage currently shows it.
type ControlView struct {
	Workspace string
	Genesis   digest.Digest
	Heads     []*Verified // sorted by digest
	verified  map[digest.Digest]*Verified
}

// Get returns a verified Control of the DAG by digest.
func (v *ControlView) Get(d digest.Digest) (*Verified, bool) {
	c, ok := v.verified[d]
	return c, ok
}

// Digests lists every verified Control, which an accepted checkpoint must stay inside.
func (v *ControlView) Digests() []digest.Digest {
	out := make([]digest.Digest, 0, len(v.verified))
	for d := range v.verified {
		out = append(out, d)
	}
	sortDigests(out)
	return out
}

// Forked reports whether the DAG has competing heads.
func (v *ControlView) Forked() bool { return len(v.Heads) > 1 }

// Head returns the single head, or a *ForkError when the DAG forked.
func (v *ControlView) Head() (*Verified, error) {
	if v.Forked() {
		return nil, &ForkError{Heads: v.Heads}
	}
	return v.Heads[0], nil
}

type pendingControl struct {
	blob []byte
	c    Control
}

// LoadControl reads and verifies the Control DAG of a workspace.
//
// genesis is the trusted digest from bootstrap information; it is fetched by
// digest, never discovered. Every other Control is accepted only when all its
// parents are, so objects an outsider published without authority are ignored.
// cp, if not nil, holds the heads this client accepted before; each must still
// be part of the DAG, otherwise storage hid something it showed us earlier.
func LoadControl(ctx context.Context, store storage.Store, workspace string, genesis digest.Digest, cp []digest.Digest) (*ControlView, error) {
	if err := validDigest(genesis); err != nil {
		return nil, invalid("trusted genesis digest: %v", err)
	}
	genesisBlob, err := store.FetchHead(ctx, storage.KindControl, "", genesis)
	if err != nil {
		return nil, fmt.Errorf("reading genesis control: %w", err)
	}
	root, err := VerifyGenesis(workspace, genesisBlob, genesis)
	if err != nil {
		return nil, err
	}
	view := &ControlView{Workspace: workspace, Genesis: genesis, verified: map[digest.Digest]*Verified{genesis: root}}

	revs, err := store.Discover(ctx, storage.KindControl, "")
	if err != nil {
		return nil, err
	}
	pending := map[digest.Digest]pendingControl{}
	total := len(genesisBlob)
	load := func(rev digest.Digest) error {
		if _, done := view.verified[rev]; done {
			return nil
		}
		if _, ok := pending[rev]; ok {
			return nil
		}
		if len(pending) >= maxControls || total > maxControlBytes {
			return invalid("control DAG is too large")
		}
		blob, err := store.FetchHead(ctx, storage.KindControl, "", rev)
		switch {
		case errors.Is(err, storage.ErrNotFound), errors.Is(err, storage.ErrCorrupt):
			return nil // listed but unavailable or damaged: it carries no authority
		case err != nil:
			return err
		}
		total += len(blob)
		s, err := DecodeSigned(blob)
		if err != nil {
			return nil
		}
		c, err := decodeControl(s.Body)
		if err != nil || c.Workspace != workspace {
			return nil
		}
		pending[rev] = pendingControl{blob: blob, c: c}
		return nil
	}
	for _, rev := range revs {
		if err := load(rev); err != nil {
			return nil, err
		}
	}
	// Parents the listing did not show can still be fetched by digest.
	for again := true; again; {
		again = false
		for _, p := range pending {
			for _, parent := range p.c.Parents {
				if _, ok := pending[parent]; !ok {
					if _, done := view.verified[parent]; !done {
						before := len(pending)
						if err := load(parent); err != nil {
							return nil, err
						}
						again = again || len(pending) != before
					}
				}
			}
		}
	}
	// Accept Controls whose parents are all accepted, until nothing changes.
	for progress := true; progress; {
		progress = false
		for rev, p := range pending {
			parents := make([]*Verified, 0, len(p.c.Parents))
			ready := len(p.c.Parents) > 0
			for _, parent := range p.c.Parents {
				pv, ok := view.verified[parent]
				if !ok {
					ready = false
					break
				}
				parents = append(parents, pv)
			}
			if !ready {
				continue
			}
			delete(pending, rev)
			progress = true
			if v, err := VerifyChild(parents, p.blob); err == nil && v.Digest == rev {
				view.verified[rev] = v
			}
		}
	}
	childOf := map[digest.Digest]bool{}
	for _, v := range view.verified {
		for _, p := range v.Parents {
			childOf[p] = true
		}
	}
	for d, v := range view.verified {
		if !childOf[d] {
			view.Heads = append(view.Heads, v)
		}
	}
	sortVerified(view.Heads)
	for _, d := range cp {
		if _, ok := view.verified[d]; !ok {
			return nil, fmt.Errorf("%w: accepted control %s is missing from storage", ErrRollback, d)
		}
	}
	return view, nil
}

func sortVerified(vs []*Verified) {
	for i := 1; i < len(vs); i++ {
		for j := i; j > 0 && vs[j].Digest < vs[j-1].Digest; j-- {
			vs[j], vs[j-1] = vs[j-1], vs[j]
		}
	}
}

// NewGenesis signs the genesis Control for a workspace founded by founder and
// returns its stored bytes and digest, without publishing anything. A caller
// that must record the digest locally can do that first and publish afterwards,
// so a failure to record it never leaves a published control nobody trusts.
func NewGenesis(workspace string, founder Principal, signer signing.Signer) ([]byte, digest.Digest, error) {
	founder.Admin = true
	blob, err := SignControl(Control{Workspace: workspace, Principals: []Principal{founder}, Author: founder.ID}, signer)
	if err != nil {
		return nil, "", err
	}
	d := digest.FromBytes(blob)
	if _, err := VerifyGenesis(workspace, blob, d); err != nil {
		return nil, "", err
	}
	return blob, d, nil
}

func publishControl(ctx context.Context, store storage.Store, blob []byte) error {
	return store.Publish(ctx, storage.Object{Kind: storage.KindControl, Rev: digest.FromBytes(blob), Head: blob})
}

// PublishGenesis stores a genesis Control from NewGenesis.
func PublishGenesis(ctx context.Context, store storage.Store, blob []byte) error {
	return publishControl(ctx, store, blob)
}

// CreateControl signs and publishes the genesis Control.
func CreateControl(ctx context.Context, store storage.Store, workspace string, founder Principal, signer signing.Signer) (*Verified, error) {
	blob, d, err := NewGenesis(workspace, founder, signer)
	if err != nil {
		return nil, err
	}
	v, err := VerifyGenesis(workspace, blob, d)
	if err != nil {
		return nil, err
	}
	if err := PublishGenesis(ctx, store, blob); err != nil {
		return nil, err
	}
	return v, nil
}

// UpdateControl signs and publishes the successor of the view's only head.
// mutate edits the principal list. signer must be an admin of the head;
// otherwise the result could never verify, so it is refused before anything is
// published. Storage has no compare-and-swap, so after publishing it loads the
// DAG again: if another admin published at the same time the result is a
// *ForkError and the caller must not treat the update as settled.
func UpdateControl(ctx context.Context, store storage.Store, view *ControlView, signer signing.Signer, mutate func(*Control) error) (*Verified, error) {
	head, err := view.Head()
	if err != nil {
		return nil, err
	}
	next := head.Control
	next.Principals = append([]Principal(nil), head.Principals...)
	next.Parents = []digest.Digest{head.Digest}
	next.Height = head.Height + 1
	next.Author = signer.Public().DeviceID()
	if a, ok := head.Principal(next.Author); !ok || !a.Admin {
		return nil, errors.New("only an admin can change the workspace control")
	}
	if err := mutate(&next); err != nil {
		return nil, err
	}
	return publishChild(ctx, store, view, []*Verified{head}, next, signer)
}

// ResolveFork publishes a Control that joins every head of a forked view. It
// starts from the principals the heads list (an admin of any head stays one);
// mutate may only remove principals or admin rights, because VerifyChild
// refuses a resolution that adds anything. signer must be an admin of every head.
func ResolveFork(ctx context.Context, store storage.Store, view *ControlView, signer signing.Signer, mutate func(*Control) error) (*Verified, error) {
	if !view.Forked() {
		return nil, errors.New("the workspace control is not forked")
	}
	author := signer.Public().DeviceID()
	next := Control{Workspace: view.Workspace, Author: author}
	var maxHeight uint64
	union := map[signing.DeviceID]Principal{}
	for _, h := range view.Heads {
		if a, ok := h.Principal(author); !ok || !a.Admin {
			return nil, errors.New("only an admin of every competing control can resolve the fork")
		}
		next.Parents = append(next.Parents, h.Digest)
		maxHeight = max(maxHeight, h.Height)
		for _, p := range h.Principals {
			if cur, ok := union[p.ID]; ok {
				p.Admin = p.Admin || cur.Admin
			}
			union[p.ID] = p
		}
	}
	sortDigests(next.Parents)
	next.Height = maxHeight + 1
	for _, p := range union {
		next.Principals = append(next.Principals, p)
	}
	if err := mutate(&next); err != nil {
		return nil, err
	}
	return publishChild(ctx, store, view, view.Heads, next, signer)
}

func publishChild(ctx context.Context, store storage.Store, view *ControlView, parents []*Verified, next Control, signer signing.Signer) (*Verified, error) {
	blob, err := SignControl(next, signer)
	if err != nil {
		return nil, err
	}
	v, err := VerifyChild(parents, blob)
	if err != nil {
		return nil, err
	}
	if err := publishControl(ctx, store, blob); err != nil {
		return nil, err
	}
	after, err := LoadControl(ctx, store, view.Workspace, view.Genesis, []digest.Digest{v.Digest})
	if err != nil {
		return nil, err
	}
	if after.Forked() {
		return nil, &ForkError{Heads: after.Heads}
	}
	return v, nil
}
