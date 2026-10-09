// Package storage publishes immutable, content-named objects. Storage is
// untrusted: a name is a locator and every fetched object is checked against
// the digest embedded in its name. There is no compare-and-swap; concurrent
// writers publish different names and readers merge the resulting heads.
package storage

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/opencontainers/go-digest"
)

const (
	// MaxPayloadBytes bounds one attached blob, such as a revision's ciphertext.
	MaxPayloadBytes = 10 * 1024 * 1024
	// MaxHeadBytes bounds the head of an object, which is read for every revision.
	MaxHeadBytes = 1024 * 1024
	// MaxBlobs bounds the blobs one object can attach.
	MaxBlobs    = 8
	scopeHexLen = 32
)

var (
	ErrNotFound    = errors.New("storage object not found")
	ErrCorrupt     = errors.New("storage object does not match its name")
	ErrTooLarge    = fmt.Errorf("payload exceeds %d bytes", MaxPayloadBytes)
	ErrUnsupported = errors.New("storage operation not supported by this backend")
)

// Kind separates the object namespaces of one storage location.
type Kind string

const (
	KindState   Kind = "state"
	KindControl Kind = "control"
	KindRequest Kind = "request"
)

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

// Object is one published revision: a head that names it, and blobs the head
// refers to. Rev is the digest of Head. Storage gives the parts no meaning; the
// protocol on top decides what the head says and what each blob is.
//
// They are separate because they are read separately: finding a resource's
// heads and merge base needs only the small heads of every revision, and a
// blob is fetched only for a revision whose content is actually needed.
type Object struct {
	Kind  Kind
	Scope string // StateScope for State, empty otherwise
	Rev   digest.Digest
	Head  []byte
	Blobs [][]byte
}

// Capabilities lists optional backend features. Correctness never depends on them.
type Capabilities struct {
	PhysicalDelete bool
}

// Store is the whole contract a backend implements.
type Store interface {
	// Publish stores the object under its content-derived name. It is create-only
	// and idempotent, and returns only after reading the object back by name, so
	// a head is never visible without the blobs it refers to.
	Publish(ctx context.Context, o Object) error
	// FetchHead returns the head, verified against its name. A missing object is
	// ErrNotFound. It never transfers the blobs.
	FetchHead(ctx context.Context, kind Kind, scope string, rev digest.Digest) ([]byte, error)
	// OpenBlob streams the index-th blob of an object (counting from 0). A missing
	// object or blob is ErrNotFound. The caller checks the content against the
	// digest its head names, because only the protocol on top knows it.
	OpenBlob(ctx context.Context, kind Kind, scope string, rev digest.Digest, index int) (io.ReadCloser, error)
	// Discover lists the revisions it can currently see. The list may be stale
	// but never names an object that does not exist.
	Discover(ctx context.Context, kind Kind, scope string) ([]digest.Digest, error)
	// Delete removes an object. Backends without Capabilities.PhysicalDelete return ErrUnsupported.
	Delete(ctx context.Context, kind Kind, scope string, rev digest.Digest) error
	Capabilities() Capabilities
}

// ReadBlob reads a whole blob of at most limit bytes.
func ReadBlob(ctx context.Context, s Store, kind Kind, scope string, rev digest.Digest, index int, limit int64) ([]byte, error) {
	rc, err := s.OpenBlob(ctx, kind, scope, rev, index)
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
	if kind != KindState {
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
	if len(o.Blobs) > MaxBlobs {
		return fmt.Errorf("an object has at most %d blobs", MaxBlobs)
	}
	for _, b := range o.Blobs {
		if len(b) == 0 {
			return errors.New("a blob must not be empty")
		}
		if len(b) > MaxPayloadBytes {
			return ErrTooLarge
		}
	}
	return nil
}

// Name is the flat tag or file name of a revision: s-<scope>-<rev>, c-<rev>, r-<rev>.
func Name(kind Kind, scope string, rev digest.Digest) (string, error) {
	if err := validateRef(kind, scope, rev); err != nil {
		return "", err
	}
	l, _ := kind.letter()
	if kind == KindState {
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
	if kind == KindState {
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

// ValidateKey checks that a name is a legal OCI tag and a legal file name.
func ValidateKey(key string) error {
	if key == "" || len(key) > 128 || key == "." || key == ".." {
		return fmt.Errorf("invalid storage key %q", key)
	}
	for _, r := range key {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' || r == '.' {
			continue
		}
		return fmt.Errorf("invalid storage key %q", key)
	}
	return nil
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
//	uvarint(parts) uvarint(len)... head blob...
//
// where the head is the first part. The lengths come first so a reader can
// reach one part with a ranged read, without transferring the others.

// maxFrameBytes bounds a stored object so a hostile backend cannot exhaust memory.
const maxFrameBytes = MaxHeadBytes + MaxBlobs*MaxPayloadBytes + (MaxBlobs+2)*binary.MaxVarintLen64

func frame(o Object) []byte {
	parts := append([][]byte{o.Head}, o.Blobs...)
	var buf bytes.Buffer
	var n [binary.MaxVarintLen64]byte
	buf.Write(n[:binary.PutUvarint(n[:], uint64(len(parts)))])
	for _, p := range parts {
		buf.Write(n[:binary.PutUvarint(n[:], uint64(len(p)))])
	}
	for _, p := range parts {
		buf.Write(p)
	}
	return buf.Bytes()
}

// frameLayout is where each part of a stored object lies.
type frameLayout struct{ offsets, lengths []int64 }

// readLayout parses the lengths at the start of an object of the given size.
func readLayout(r io.ReaderAt, size int64) (frameLayout, error) {
	headerMax := int64((MaxBlobs + 2) * binary.MaxVarintLen64)
	buf := make([]byte, min(size, headerMax))
	if _, err := r.ReadAt(buf, 0); err != nil && !errors.Is(err, io.EOF) {
		return frameLayout{}, err
	}
	count, n := binary.Uvarint(buf)
	if n <= 0 || count == 0 || count > MaxBlobs+1 {
		return frameLayout{}, fmt.Errorf("%w: malformed object", ErrCorrupt)
	}
	var l frameLayout
	pos := int64(n)
	var total uint64
	for i := uint64(0); i < count; i++ {
		v, m := binary.Uvarint(buf[pos:])
		if m <= 0 {
			return frameLayout{}, fmt.Errorf("%w: malformed object", ErrCorrupt)
		}
		pos += int64(m)
		l.lengths = append(l.lengths, int64(v))
		total += v
	}
	if l.lengths[0] == 0 || l.lengths[0] > MaxHeadBytes || total > maxFrameBytes || int64(total) != size-pos {
		return frameLayout{}, fmt.Errorf("%w: malformed object", ErrCorrupt)
	}
	off := pos
	for _, length := range l.lengths {
		l.offsets = append(l.offsets, off)
		off += length
	}
	return l, nil
}

// readHead reads and verifies the head of a stored object.
func readHead(r io.ReaderAt, size int64, rev digest.Digest) ([]byte, frameLayout, error) {
	l, err := readLayout(r, size)
	if err != nil {
		return nil, l, err
	}
	head := make([]byte, l.lengths[0])
	if _, err := r.ReadAt(head, l.offsets[0]); err != nil && !errors.Is(err, io.EOF) {
		return nil, l, err
	}
	if digest.FromBytes(head) != rev {
		return nil, l, fmt.Errorf("%w: head does not match its revision", ErrCorrupt)
	}
	return head, l, nil
}

// blobSection is a reader over one blob of a stored object.
func blobSection(r io.ReaderAt, l frameLayout, index int) (*io.SectionReader, error) {
	if index < 0 || index+1 >= len(l.offsets) {
		return nil, fmt.Errorf("%w: the object has no blob %d", ErrNotFound, index)
	}
	return io.NewSectionReader(r, l.offsets[index+1], l.lengths[index+1]), nil
}
