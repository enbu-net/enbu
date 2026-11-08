package wsp

import (
	"context"
	"errors"
	"fmt"
	"sync"

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
//
// Generation is 1 + the highest Generation of the parents, 1 without parents.
// It only grows along the DAG, so a device that accepted a generation detects
// storage showing an older view (see Checkpoints).
type State struct {
	Workspace  string           `cbor:"workspace"`
	Resource   string           `cbor:"resource"`
	Parents    []digest.Digest  `cbor:"parents"` // sorted, unique
	Generation uint64           `cbor:"generation"`
	Op         string           `cbor:"op"`      // what made the revision, one of the Op constants
	Control    digest.Digest    `cbor:"control"` // Control revision the author saw
	Ciphertext digest.Digest    `cbor:"ciphertext"`
	Author     signing.DeviceID `cbor:"author"`
	CreatedAt  int64            `cbor:"created_at"` // unix seconds; display only, never used for ordering decisions
}

// The kinds of revision. A sync with one parent only re-encrypts its content.
const (
	OpWrite   = "write"   // a person changed secrets: add, edit, delete, import
	OpSync    = "sync"    // re-encryption, and merging concurrent heads
	OpRestore = "restore" // the content of an older revision, published again
	OpResolve = "resolve" // merging heads with the values a person chose
)

// TopGeneration is the highest Generation of states, or 0 if there are none.
func TopGeneration(states []*VerifiedState) uint64 {
	var top uint64
	for _, st := range states {
		top = max(top, st.Generation)
	}
	return top
}

// NextGeneration is the Generation of a revision whose parents are parents.
func NextGeneration(parents []*VerifiedState) uint64 { return TopGeneration(parents) + 1 }

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
	if s.Generation == 0 || (s.Generation == 1) != (len(s.Parents) == 0) {
		return invalid("state generation %d does not fit %d parents", s.Generation, len(s.Parents))
	}
	switch s.Op {
	case OpWrite, OpSync, OpRestore, OpResolve:
	default:
		return invalid("state has an unknown op %q", s.Op)
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
// as the current value, while its author has remained a member. Rejoining
// must not revive an unaccepted revision signed before removal.
func AuthorIsCurrent(view *ControlView, head *Verified, st *VerifiedState) error {
	if _, ok := head.Principal(st.Author); !ok {
		return invalid("state author %s is no longer a principal of the workspace", st.Author)
	}
	if !view.MembershipUnbroken(head.Digest, st.Control, st.Author) {
		return invalid("state author %s was removed after the control it names", st.Author)
	}
	return nil
}

// StateView is the verified revision DAG of one resource as storage shows it.
// A parent missing from it is history that was deleted: the DAG ends there.
type StateView struct {
	Graph   *Graph
	States  map[digest.Digest]*VerifiedState
	Heads   []*VerifiedState // sorted by digest
	Skipped int              // listed revisions that failed to fetch or verify
}

// MaxGeneration is the highest Generation of the verified revisions in the
// view, whoever wrote them, or 0 for an empty view. It measures how fresh the
// view is, not what may be read: see Checkpoints.
func (sv *StateView) MaxGeneration() uint64 {
	var top uint64
	if sv != nil {
		for _, st := range sv.States {
			top = max(top, st.Generation)
		}
	}
	return top
}

// StateResource reads the workspace and resource a stored state names, without
// verifying anything. The answer is untrusted; it only tells a caller that
// found a revision by listing storage which resource to verify it against.
func StateResource(blob []byte) (workspace, resource string, err error) {
	signed, err := DecodeSigned(blob)
	if err != nil {
		return "", "", err
	}
	var s State
	if err := decodeCanonical(signed.Body, &s); err != nil {
		return "", "", err
	}
	if err := s.validate(); err != nil {
		return "", "", err
	}
	return s.Workspace, s.Resource, nil
}

// maxRevisions bounds how many revisions one load reads.
var (
	maxRevisions = 20000
	// Bound aggregate metadata bytes, including invalid objects. One parallel
	// prefetch batch can already be in flight; no later batch is started.
	maxStateBytes = 32 << 20
)

// LoadStates reads the head of every revision of a resource that storage lists,
// plus any ancestors the listing missed, and verifies each against the Control
// DAG. It never transfers a ciphertext: the DAG needs only the heads, and a
// ciphertext is read (OpenCiphertext) for the few revisions whose content is used.
// Revisions that are damaged or unauthorized carry no authority and are skipped.
// also lists revisions to include even if the listing does not show them.
// A revision naming a parent storage cannot produce ends the history there. A
// revision whose parents are all present must carry the Generation they imply;
// one that does not is skipped like any other invalid revision.
func LoadStates(ctx context.Context, store storage.Store, view *ControlView, workspace, resource string, also ...digest.Digest) (*StateView, error) {
	scope := storage.StateScope(workspace, resource)
	revs, err := store.Discover(ctx, storage.KindState, scope)
	if err != nil {
		return nil, err
	}
	if len(revs) > maxRevisions {
		return nil, invalid("resource has too many revisions")
	}
	sv := &StateView{Graph: NewGraph(), States: map[digest.Digest]*VerifiedState{}}
	tried := map[digest.Digest]bool{}
	// also names revisions the caller knows exist, such as one it just published
	// that a stale listing may not show yet.
	totalBytes := 0
	queue := append(append([]digest.Digest(nil), revs...), also...)
	for len(queue) > 0 {
		batch := make([]digest.Digest, 0, headFetches)
		for len(queue) > 0 && len(batch) < headFetches {
			rev := queue[0]
			queue = queue[1:]
			if tried[rev] {
				continue
			}
			tried[rev] = true
			if len(tried) > maxRevisions {
				return nil, invalid("resource has too many revisions")
			}
			batch = append(batch, rev)
		}
		fetched, err := prefetchHeads(ctx, store, scope, batch)
		if err != nil {
			return nil, err
		}
		for _, rev := range batch {
			f := fetched[rev]
			switch {
			case errors.Is(f.err, storage.ErrNotFound), errors.Is(f.err, storage.ErrCorrupt):
				sv.Skipped++
				continue
			}
			if len(f.head) > maxStateBytes-totalBytes {
				return nil, invalid("resource metadata exceeds the read budget")
			}
			totalBytes += len(f.head)
			st, err := VerifyRevision(view, workspace, resource, rev, f.head)
			if err != nil {
				if errors.Is(err, ErrRollback) {
					return nil, err
				}
				sv.Skipped++
				continue
			}
			sv.States[rev] = st
			sv.Graph.Add(rev, st.Parents)
			queue = append(queue, st.Parents...)
		}
	}

	sv.dropWrongGenerations()
	for _, d := range sv.Graph.Heads() {
		sv.Heads = append(sv.Heads, sv.States[d])
	}
	return sv, nil
}

// dropWrongGenerations removes revisions whose parents are all present but
// whose Generation is not the one they imply. Missing parents were deleted, so
// their generations cannot be checked.
func (sv *StateView) dropWrongGenerations() {
	var wrong []digest.Digest
	for d, st := range sv.States {
		parents := make([]*VerifiedState, 0, len(st.Parents))
		for _, p := range st.Parents {
			if ps, ok := sv.States[p]; ok {
				parents = append(parents, ps)
			}
		}
		if len(parents) == len(st.Parents) && st.Generation != NextGeneration(parents) {
			wrong = append(wrong, d)
		}
	}
	if len(wrong) == 0 {
		return
	}
	for _, d := range wrong {
		delete(sv.States, d)
		sv.Skipped++
	}
	sv.Graph = NewGraph()
	for d, st := range sv.States {
		sv.Graph.Add(d, st.Parents)
	}
}

// With returns a copy of the view that also holds st, such as a revision the
// caller just published on top of it. sv may be nil for a resource that had no
// revision yet.
func (sv *StateView) With(st *VerifiedState) *StateView {
	out := &StateView{Graph: NewGraph(), States: map[digest.Digest]*VerifiedState{}}
	if sv != nil {
		for d, v := range sv.States {
			out.States[d] = v
			out.Graph.Add(d, v.Parents)
		}
		out.Skipped = sv.Skipped
	}
	out.States[st.Digest] = st
	out.Graph.Add(st.Digest, st.Parents)
	for _, d := range out.Graph.Heads() {
		out.Heads = append(out.Heads, out.States[d])
	}
	return out
}

// headFetches bounds how many heads LoadStates fetches at once.
const headFetches = 8

type fetchedHead struct {
	head []byte
	err  error
}

type serialHeadReadsKey struct{}

// WithSerialHeadReads disables speculative parallel fetches for a caller that
// schedules external effects itself. Verification and error handling are identical.
func WithSerialHeadReads(ctx context.Context) context.Context {
	return context.WithValue(ctx, serialHeadReadsKey{}, true)
}

func terminalHeadError(err error) bool {
	return err != nil && !errors.Is(err, storage.ErrNotFound) && !errors.Is(err, storage.ErrCorrupt)
}

// prefetchHeads fetches one bounded batch. Terminal failures cancel the other
// requests; the caller verifies and releases this batch before fetching more.
func prefetchHeads(ctx context.Context, store storage.Store, scope string, revs []digest.Digest) (map[digest.Digest]fetchedHead, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	out := make(map[digest.Digest]fetchedHead, len(revs))
	if serial, _ := ctx.Value(serialHeadReadsKey{}).(bool); serial {
		for _, rev := range revs {
			head, err := store.FetchHead(ctx, storage.KindState, scope, rev)
			out[rev] = fetchedHead{head, err}
			if terminalHeadError(err) {
				return nil, err
			}
		}
		return out, ctx.Err()
	}

	var mu sync.Mutex
	var wg sync.WaitGroup
	var failure error
	for _, rev := range revs {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			head, err := store.FetchHead(ctx, storage.KindState, scope, rev)
			mu.Lock()
			defer mu.Unlock()
			out[rev] = fetchedHead{head, err}
			if terminalHeadError(err) && failure == nil {
				failure = err
				cancel()
			}
		}()
	}
	wg.Wait()
	if failure != nil {
		return nil, failure
	}
	return out, ctx.Err()
}

// MaxCiphertextBytes bounds one revision's ciphertext.
const MaxCiphertextBytes = storage.MaxPayloadBytes

// ReadCiphertext reads the ciphertext of a verified revision and checks it is
// the one the signed State names. It is attached to the revision as its only
// blob; anything else storage holds there is refused.
func ReadCiphertext(ctx context.Context, store storage.Store, st *VerifiedState) ([]byte, error) {
	data, err := storage.ReadBlob(ctx, store, storage.KindState, st.Scope(), st.Digest, 0, MaxCiphertextBytes)
	if err != nil {
		return nil, err
	}
	if digest.FromBytes(data) != st.Ciphertext {
		return nil, fmt.Errorf("%w: ciphertext does not match the signed state", storage.ErrCorrupt)
	}
	return data, nil
}
