// Package storage publishes immutable, content-named objects. Storage is
// untrusted: a name is a locator and every fetched object is checked against
// the digest embedded in its name. There is no compare-and-swap; concurrent
// writers publish different names and readers merge the resulting heads.
package storage

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/opencontainers/go-digest"
)

const (
	// MaxPayloadBytes bounds the payload of an object, such as a revision's ciphertext.
	MaxPayloadBytes = 10 * 1024 * 1024
	// MaxHeadBytes bounds the head of an object, which is read for every revision.
	MaxHeadBytes = 1024 * 1024
	scopeHexLen  = 32
	// MaxRequestRefs bounds request discovery before all pages are accumulated.
	// Duplicate refs consume the budget too: a hostile listing may repeat them.
	MaxRequestRefs = 10000
)

var (
	ErrNotFound       = errors.New("storage object not found")
	ErrCorrupt        = errors.New("storage object does not match its name")
	ErrTooLarge       = fmt.Errorf("payload exceeds %d bytes", MaxPayloadBytes)
	ErrUnsupported    = errors.New("storage cannot delete objects")
	ErrDiscoveryLimit = errors.New("request discovery exceeds the reference budget")
)

// Kind separates the object namespaces of one storage location.
type Kind string

const (
	KindState   Kind = "state"
	KindControl Kind = "control"
	KindRequest Kind = "request"
)

// scoped reports whether objects of the kind belong to a state scope.
func (k Kind) scoped() bool { return k == KindState }

func (k Kind) letter() (string, bool) {
	switch k {
	case KindState:
		return "s", true
	case KindControl:
		return "c", true
	case KindRequest:
		return "r", true
	}
	return "", false
}

// Object is one published revision: a head that names it, and an optional
// payload the head refers to. Rev is the digest of Head. Storage gives the
// parts no meaning; the protocol on top decides what they say.
//
// They are separate because they are read separately: finding a resource's
// heads and merge base needs only the small heads of every revision, and a
// payload is fetched only for a revision whose content is actually needed.
type Object struct {
	Kind    Kind
	Scope   string // StateScope for State, empty otherwise
	Rev     digest.Digest
	Head    []byte
	Payload []byte // empty for none
}

// Store is the whole contract a backend implements.
type Store interface {
	// Publish stores the object under its content-derived name. It is create-only
	// and idempotent, and returns only after reading the object back by name, so
	// a head is never visible without its payload.
	Publish(ctx context.Context, o Object) error
	// FetchHead returns the head, verified against its name. A missing object is
	// ErrNotFound. It never transfers the payload.
	FetchHead(ctx context.Context, kind Kind, scope string, rev digest.Digest) ([]byte, error)
	// OpenPayload streams the payload of an object. A missing object or payload
	// is ErrNotFound. The caller checks the content against the digest its head
	// names, because only the protocol on top knows it.
	OpenPayload(ctx context.Context, kind Kind, scope string, rev digest.Digest) (io.ReadCloser, error)
	// Discover lists the revisions it can currently see. The list may be stale
	// but never names an object that does not exist. Request discovery stops at
	// MaxRequestRefs and returns ErrDiscoveryLimit without a partial list.
	Discover(ctx context.Context, kind Kind, scope string) ([]digest.Digest, error)
	// Scopes lists the state scopes that hold at least one revision it can
	// currently see, sorted. Like Discover it may be stale.
	Scopes(ctx context.Context) ([]string, error)
	// Delete removes an object. A backend that cannot delete returns ErrUnsupported.
	Delete(ctx context.Context, kind Kind, scope string, rev digest.Digest) error
}

// ReadPayload reads a whole payload of at most limit bytes.
func ReadPayload(ctx context.Context, s Store, kind Kind, scope string, rev digest.Digest, limit int64) ([]byte, error) {
	rc, err := s.OpenPayload(ctx, kind, scope, rev)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rc.Close() }()
	data, err := io.ReadAll(io.LimitReader(rc, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, ErrTooLarge
	}
	return data, nil
}

// StateScope names the listing bucket of one resource of a workspace. A scope
// collision only mixes two resources in one listing: fetchers re-derive the
// scope from the signed workspace and resource.
func StateScope(workspace, resource string) string {
	// Length-prefixed fields keep (workspace, resource) pairs unambiguous.
	sum := sha256.Sum256([]byte(fmt.Sprintf("enbu.state-scope.v1\x00%d:%s%d:%s", len(workspace), workspace, len(resource), resource)))
	return hex.EncodeToString(sum[:])[:scopeHexLen]
}

func validScope(kind Kind, scope string) error {
	if !kind.scoped() {
		if scope != "" {
			return fmt.Errorf("%s objects have no scope", kind)
		}
		return nil
	}
	if len(scope) != scopeHexLen {
		return fmt.Errorf("invalid state scope %q", scope)
	}
	for _, r := range scope {
		if r >= '0' && r <= '9' || r >= 'a' && r <= 'f' {
			continue
		}
		return fmt.Errorf("invalid state scope %q", scope)
	}
	return nil
}

func validateRef(kind Kind, scope string, rev digest.Digest) error {
	if _, ok := kind.letter(); !ok {
		return fmt.Errorf("unknown storage kind %q", kind)
	}
	if err := validScope(kind, scope); err != nil {
		return err
	}
	return ValidateDigest(rev)
}

// ValidateObject checks everything about an object that does not need the backend.
func ValidateObject(o Object) error {
	if err := validateRef(o.Kind, o.Scope, o.Rev); err != nil {
		return err
	}
	if len(o.Head) == 0 || len(o.Head) > MaxHeadBytes {
		return fmt.Errorf("head must be 1..%d bytes", MaxHeadBytes)
	}
	if digest.FromBytes(o.Head) != o.Rev {
		return fmt.Errorf("%w: revision is not the digest of the head", ErrCorrupt)
	}
	if len(o.Payload) > MaxPayloadBytes {
		return ErrTooLarge
	}
	return nil
}

// Name is the flat tag or file name of a revision: s-<scope>-<rev>, c-<rev>,
// r-<rev>.
func Name(kind Kind, scope string, rev digest.Digest) (string, error) {
	if err := validateRef(kind, scope, rev); err != nil {
		return "", err
	}
	l, _ := kind.letter()
	if kind.scoped() {
		return l + "-" + scope + "-" + rev.Encoded(), nil
	}
	return l + "-" + rev.Encoded(), nil
}

// namePrefix is the part of a name shared by every revision of a scope.
func namePrefix(kind Kind, scope string) (string, error) {
	if _, ok := kind.letter(); !ok {
		return "", fmt.Errorf("unknown storage kind %q", kind)
	}
	if err := validScope(kind, scope); err != nil {
		return "", err
	}
	l, _ := kind.letter()
	if kind.scoped() {
		return l + "-" + scope + "-", nil
	}
	return l + "-", nil
}

// revFromName extracts the revision from a listed name, or reports that the
// name does not belong to the scope or is malformed.
func revFromName(prefix, name string) (digest.Digest, bool) {
	if !strings.HasPrefix(name, prefix) {
		return "", false
	}
	h := strings.TrimPrefix(name, prefix)
	if len(h) != 64 {
		return "", false
	}
	d := digest.NewDigestFromEncoded(digest.SHA256, h)
	if d.Validate() != nil {
		return "", false
	}
	return d, true
}

// scopeFromName extracts the state scope from a listed name, or reports that
// the name is not a well-formed state revision.
func scopeFromName(name string) (string, bool) {
	l, _ := KindState.letter()
	rest, ok := strings.CutPrefix(name, l+"-")
	if !ok || len(rest) <= scopeHexLen || rest[scopeHexLen] != '-' {
		return "", false
	}
	scope := rest[:scopeHexLen]
	if validScope(KindState, scope) != nil {
		return "", false
	}
	if _, ok := revFromName(l+"-"+scope+"-", name); !ok {
		return "", false
	}
	return scope, true
}

// sortedScopes returns the distinct state scopes among names, sorted.
func sortedScopes(names []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, n := range names {
		if scope, ok := scopeFromName(n); ok && !seen[scope] {
			seen[scope] = true
			out = append(out, scope)
		}
	}
	sort.Strings(out)
	return out
}

func ValidateDigest(d digest.Digest) error {
	// Validate first: Algorithm panics on a digest without a separator.
	if err := d.Validate(); err != nil {
		return err
	}
	if d.Algorithm() != digest.SHA256 {
		return fmt.Errorf("unsupported digest %q", d)
	}
	return nil
}

// A single-file backend (S3, local) stores an object as
//
//	uvarint(len(head)) head payload
//
// so a reader reaches the head, or the payload after it, with a ranged read.

// maxFrameBytes bounds a stored object so a hostile backend cannot exhaust memory.
const maxFrameBytes = binary.MaxVarintLen64 + MaxHeadBytes + MaxPayloadBytes

func frame(o Object) []byte {
	var n [binary.MaxVarintLen64]byte
	out := append([]byte(nil), n[:binary.PutUvarint(n[:], uint64(len(o.Head)))]...)
	out = append(out, o.Head...)
	return append(out, o.Payload...)
}

// readHead reads and verifies the head of a stored object of the given size,
// and returns where the payload starts.
func readHead(r io.ReaderAt, size int64, rev digest.Digest) ([]byte, int64, error) {
	buf := make([]byte, min(size, binary.MaxVarintLen64))
	if _, err := r.ReadAt(buf, 0); err != nil && !errors.Is(err, io.EOF) {
		return nil, 0, err
	}
	length, n := binary.Uvarint(buf)
	// The head has its own bound, checked before anything is added, so a length
	// a hostile backend made huge cannot place the head outside the object.
	if n <= 0 || length == 0 || length > MaxHeadBytes || int64(n)+int64(length) > size || size-int64(n)-int64(length) > MaxPayloadBytes {
		return nil, 0, fmt.Errorf("%w: malformed object", ErrCorrupt)
	}
	head := make([]byte, length)
	if _, err := r.ReadAt(head, int64(n)); err != nil && !errors.Is(err, io.EOF) {
		return nil, 0, err
	}
	if digest.FromBytes(head) != rev {
		return nil, 0, fmt.Errorf("%w: head does not match its revision", ErrCorrupt)
	}
	return head, int64(n) + int64(length), nil
}

// payloadSection is a reader over the payload of a stored object.
func payloadSection(r io.ReaderAt, size, offset int64) (*io.SectionReader, error) {
	if offset == size {
		return nil, fmt.Errorf("%w: the object has no payload", ErrNotFound)
	}
	return io.NewSectionReader(r, offset, size-offset), nil
}
