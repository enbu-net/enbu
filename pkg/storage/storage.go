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
	"strings"

	"github.com/opencontainers/go-digest"
)

const (
	// MaxPayloadBytes bounds the ciphertext of one revision.
	MaxPayloadBytes = 10 * 1024 * 1024
	// MaxSignedBytes bounds the signed header of one object.
	MaxSignedBytes = 1024 * 1024
	scopeHexLen    = 32
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

// Object is one published revision. Rev is the digest of Signed. Cipher is the
// ciphertext a State names; it is empty for every other kind.
type Object struct {
	Kind   Kind
	Scope  string // StateScope for State, empty otherwise
	Rev    digest.Digest
	Signed []byte
	Cipher []byte
}

// Capabilities lists optional backend features. Correctness never depends on them.
type Capabilities struct {
	PhysicalDelete bool
}

// Store is the whole contract a backend implements.
type Store interface {
	// Publish stores the object under its content-derived name. It is create-only
	// and idempotent, and returns only after reading the object back by name.
	Publish(ctx context.Context, o Object) error
	// Fetch returns the object, verified against its name. A missing object is ErrNotFound.
	Fetch(ctx context.Context, kind Kind, scope string, rev digest.Digest) (Object, error)
	// Discover lists the revisions it can currently see. The list may be stale
	// but never names an object that does not exist.
	Discover(ctx context.Context, kind Kind, scope string) ([]digest.Digest, error)
	// Delete removes an object. Backends without Capabilities.PhysicalDelete return ErrUnsupported.
	Delete(ctx context.Context, kind Kind, scope string, rev digest.Digest) error
	Capabilities() Capabilities
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
	if len(o.Signed) == 0 || len(o.Signed) > MaxSignedBytes {
		return fmt.Errorf("signed object must be 1..%d bytes", MaxSignedBytes)
	}
	if digest.FromBytes(o.Signed) != o.Rev {
		return fmt.Errorf("%w: revision is not the digest of the signed bytes", ErrCorrupt)
	}
	if o.Kind == KindState {
		if len(o.Cipher) == 0 {
			return errors.New("state object has no ciphertext")
		}
		if len(o.Cipher) > MaxPayloadBytes {
			return ErrTooLarge
		}
	} else if len(o.Cipher) != 0 {
		return fmt.Errorf("%s objects carry no ciphertext", o.Kind)
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

// frame packs the two parts of an object into one byte string for backends
// that store a revision as a single file or object.
func frame(o Object) []byte {
	var buf bytes.Buffer
	var n [binary.MaxVarintLen64]byte
	buf.Write(n[:binary.PutUvarint(n[:], uint64(len(o.Signed)))])
	buf.Write(o.Signed)
	buf.Write(o.Cipher)
	return buf.Bytes()
}

// unframe splits and verifies bytes read from a backend against the requested name.
func unframe(kind Kind, scope string, rev digest.Digest, data []byte) (Object, error) {
	n, read := binary.Uvarint(data)
	if read <= 0 || n == 0 || n > MaxSignedBytes || uint64(len(data)-read) < n {
		return Object{}, fmt.Errorf("%w: malformed object", ErrCorrupt)
	}
	o := Object{Kind: kind, Scope: scope, Rev: rev, Signed: data[read : read+int(n)]}
	if rest := data[read+int(n):]; len(rest) > 0 {
		o.Cipher = rest
	}
	if err := ValidateObject(o); err != nil {
		return Object{}, fmt.Errorf("%w: %w", ErrCorrupt, err)
	}
	return o, nil
}

// maxFrameBytes bounds a stored frame so a hostile backend cannot exhaust memory.
const maxFrameBytes = MaxPayloadBytes + MaxSignedBytes + binary.MaxVarintLen64
