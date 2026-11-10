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
// signed it validly. A State naming a Control the verified DAG does not hold
// cannot be checked, so it is invalid like any other unverifiable object:
// anyone able to write to storage can name an arbitrary Control, and treating
// it as a rollback would let one unsigned object block a resource. A hidden
// Control is detected by the Control checkpoint, a hidden State by the State checkpoint.
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
		return nil, invalid("state names control %s that is not part of the verified control", s.Control)
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
type StateView struct {
	Graph   *Graph
	States  map[digest.Digest]*VerifiedState
	Heads   []*VerifiedState // sorted by digest
	Skipped int              // listed revisions that failed to fetch or verify
	// Compacted is what verified compaction records say about the view. The
	// caller fills it in when the view lacks something (see LoadCompactions).
	Compacted Compacted
}

// MissingParents lists the parents revisions name that are neither in the view
// nor removed by a compaction.
func (sv *StateView) MissingParents() []digest.Digest {
	var out []digest.Digest
	for _, d := range sv.Graph.Missing() {
		if !sv.Compacted.Excuses(d) {
			out = append(out, d)
		}
	}
	return out
}

// maxRevisions bounds how many revisions one load reads.
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
// A revision naming a parent storage cannot produce leaves the view incomplete,
// which the caller sees as Graph.Missing.
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
				sv.Skipped++
				continue
			}
			sv.States[rev] = st
			sv.Graph.Add(rev, st.Parents)
			queue = append(queue, st.Parents...)
		}
	}

	for _, d := range sv.Graph.Heads() {
		sv.Heads = append(sv.Heads, sv.States[d])
	}
	return sv, nil
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
		out.Compacted = sv.Compacted
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
	data, err := storage.ReadPayload(ctx, store, storage.KindState, st.Scope(), st.Digest, MaxCiphertextBytes)
	if err != nil {
		return nil, err
	}
	if digest.FromBytes(data) != st.Ciphertext {
		return nil, fmt.Errorf("%w: ciphertext does not match the signed state", storage.ErrCorrupt)
	}
	return data, nil
}
