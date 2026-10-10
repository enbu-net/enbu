package wsp

import (
	"context"
	"errors"
	"fmt"

	"github.com/enbu-net/enbu/pkg/signing"
	"github.com/enbu-net/enbu/pkg/storage"
	"github.com/opencontainers/go-digest"
)

// State binds one ciphertext to the device that published it. The resource
// names what the ciphertext is (for example "secrets/prod"); it is a plain
// string so authorization can later be decided per resource by policy.
//
// States form a DAG: Parents are the revisions the author saw and merged. The
// first revision of a resource has no parents.
type State struct {
	Workspace  string           `cbor:"workspace"`
	Resource   string           `cbor:"resource"`
	Parents    []digest.Digest  `cbor:"parents"` // sorted, unique
	Control    digest.Digest    `cbor:"control"` // Control revision the author saw
	Ciphertext digest.Digest    `cbor:"ciphertext"`
	Author     signing.DeviceID `cbor:"author"`
	CreatedAt  int64            `cbor:"created_at"` // unix seconds; display only, never used for ordering decisions
}

// VerifiedState is a State whose author and signature have been checked
// against the Control it names. Digest is the digest of the SignedState bytes,
// which is the revision's identity.
type VerifiedState struct {
	State
	Digest digest.Digest
}

// Scope is the storage listing bucket of the state's resource.
func (s State) Scope() string { return storage.StateScope(s.Workspace, s.Resource) }

func (s State) validate() error {
	if s.Workspace == "" || s.Resource == "" {
		return invalid("state has no workspace or resource")
	}
	if len(s.Parents) > MaxParents {
		return invalid("state has too many parents")
	}
	for i, p := range s.Parents {
		if err := validDigest(p); err != nil {
			return invalid("state parent: %v", err)
		}
		if i > 0 && s.Parents[i-1] >= p {
			return invalid("state parents must be sorted and unique")
		}
	}
	if err := validDigest(s.Control); err != nil {
		return invalid("state control: %v", err)
	}
	if err := validDigest(s.Ciphertext); err != nil {
		return invalid("state ciphertext: %v", err)
	}
	if err := s.Author.Validate(); err != nil {
		return invalid("state author: %v", err)
	}
	return nil
}

// MaxParents bounds how many heads one revision can merge.
const MaxParents = 64

// SignState signs s, whose Author must be signer, and returns the stored bytes.
func SignState(s State, signer signing.Signer) ([]byte, error) {
	sortDigests(s.Parents)
	if err := s.validate(); err != nil {
		return nil, err
	}
	if signer.Public().DeviceID() != s.Author {
		return nil, invalid("signer is not the state author")
	}
	body, err := encMode.Marshal(s)
	if err != nil {
		return nil, err
	}
	sig, err := signer.Sign(signing.DomainState, body)
	if err != nil {
		return nil, err
	}
	return Signed{Body: body, Signature: sig}.Encode()
}

// VerifyRevision checks one stored revision of workspace and resource against
// the Control it names. The author must be a principal of that Control and the
// signature must verify under the key it lists; a member removed since still
// signed it validly. The named Control must be part of the verified DAG: one
// that is not means storage showed an older Control DAG than the author saw,
// which is reported as a rollback.
//
// It makes no claim about freshness or about whether the author is a member
// now; see AuthorIsCurrent for revisions that become the head.
func VerifyRevision(view *ControlView, workspace, resource string, rev digest.Digest, blob []byte) (*VerifiedState, error) {
	if digest.FromBytes(blob) != rev {
		return nil, invalid("state does not match its revision %s", rev)
	}
	signed, err := DecodeSigned(blob)
	if err != nil {
		return nil, err
	}
	var s State
	if err := decodeCanonical(signed.Body, &s); err != nil {
		return nil, err
	}
	if err := s.validate(); err != nil {
		return nil, err
	}
	if s.Workspace != workspace || s.Resource != resource {
		return nil, invalid("state is for %s/%s, not %s/%s", s.Workspace, s.Resource, workspace, resource)
	}
	written, ok := view.Get(s.Control)
	if !ok {
		return nil, fmt.Errorf("%w: state names control %s that storage does not show", ErrRollback, s.Control)
	}
	author, ok := written.Principal(s.Author)
	if !ok {
		return nil, invalid("state author %s is not a principal of the control it names", s.Author)
	}
	if err := signing.Verify(author.Signing, signing.DomainState, signed.Body, signed.Signature); err != nil {
		return nil, invalid("state signature: %v", err)
	}
	return &VerifiedState{State: s, Digest: rev}, nil
}

// AuthorIsCurrent reports whether the author of st is still a principal of the
// current Control. A revision may only be the head of a resource, and so be read
// as the current value, while its author is.
func AuthorIsCurrent(head *Verified, st *VerifiedState) error {
	if _, ok := head.Principal(st.Author); !ok {
		return invalid("state author %s is no longer a principal of the workspace", st.Author)
	}
	return nil
}

// StateView is the verified revision DAG of one resource as storage shows it.
type StateView struct {
	Graph   *Graph
	States  map[digest.Digest]*VerifiedState
	Heads   []*VerifiedState // sorted by digest
	Skipped int              // listed revisions that failed to fetch or verify
}

// maxRevisions bounds how many revisions one load reads.
var maxRevisions = 20000

// LoadStates reads every revision of a resource that storage lists, plus any
// ancestors the listing missed, and verifies each against the Control DAG.
// Revisions that are damaged or unauthorized carry no authority and are skipped.
// also lists revisions to include even if the listing does not show them.
// A revision naming a parent storage cannot produce leaves the view incomplete,
// which the caller sees as Graph.Missing.
func LoadStates(ctx context.Context, store storage.Store, view *ControlView, workspace, resource string, also ...digest.Digest) (*StateView, error) {
	scope := storage.StateScope(workspace, resource)
	revs, err := store.Discover(ctx, storage.KindState, scope)
	if err != nil {
		return nil, err
	}
	sv := &StateView{Graph: NewGraph(), States: map[digest.Digest]*VerifiedState{}}
	tried := map[digest.Digest]bool{}
	// also names revisions the caller knows exist, such as one it just published
	// that a stale listing may not show yet.
	queue := append(append([]digest.Digest(nil), revs...), also...)
	for len(queue) > 0 {
		rev := queue[0]
		queue = queue[1:]
		if tried[rev] {
			continue
		}
		tried[rev] = true
		if len(tried) > maxRevisions {
			return nil, invalid("resource has too many revisions")
		}
		o, err := store.Fetch(ctx, storage.KindState, scope, rev)
		switch {
		case errors.Is(err, storage.ErrNotFound), errors.Is(err, storage.ErrCorrupt):
			sv.Skipped++
			continue
		case err != nil:
			return nil, err
		}
		st, err := VerifyRevision(view, workspace, resource, rev, o.Signed)
		if err != nil {
			if errors.Is(err, ErrRollback) {
				return nil, err
			}
			sv.Skipped++
			continue
		}
		sv.States[rev] = st
		sv.Graph.Add(rev, st.Parents)
		queue = append(queue, st.Parents...) // ancestors a stale listing hid
	}
	for _, d := range sv.Graph.Heads() {
		sv.Heads = append(sv.Heads, sv.States[d])
	}
	return sv, nil
}
