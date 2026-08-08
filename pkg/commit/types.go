// Package commit defines the canonical, signed plaintext carried by enbu's
// encrypted commit objects and validates commit history as an immutable DAG.
package commit

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/enbu-net/enbu/pkg/artifact"
	"github.com/opencontainers/go-digest"
	"golang.org/x/text/unicode/norm"
)

const (
	// APIVersion is the only commit plaintext version accepted by this package.
	APIVersion = artifact.APIVersion
	Kind       = "Commit"

	MaxCommitBytes       = 16 * 1024 * 1024
	MaxParents           = 64
	MaxProvenanceRecords = 10_000
	MaxInputsPerRecord   = 10_000
	MaxActorBytes        = 253

	timestampLayout = "2006-01-02T15:04:05.000000000Z"
)

var (
	ErrInvalidCommit        = errors.New("invalid commit")
	ErrNonCanonicalCommit   = errors.New("non-canonical commit encoding")
	ErrInvalidSignature     = errors.New("invalid commit signature")
	ErrSigningKeyBinding    = errors.New("invalid or ambiguous commit signing key binding")
	ErrInvalidCommitDAG     = errors.New("invalid commit DAG")
	ErrCommitNotFound       = errors.New("commit not found")
	ErrCommitDigestMismatch = errors.New("commit digest mismatch")
)

// Timestamp is canonical UTC RFC 3339 text with exactly nanosecond precision.
// Keeping it as text avoids CBOR time tags and platform-dependent time codecs.
type Timestamp string

// NewTimestamp returns the canonical representation of value in UTC.
func NewTimestamp(value time.Time) Timestamp {
	return Timestamp(value.UTC().Format(timestampLayout))
}

// ParseTimestamp accepts only the exact wire form used by NewTimestamp.
func ParseTimestamp(value string) (Timestamp, error) {
	if len(value) != len(timestampLayout) {
		return "", fmt.Errorf("%w: timestamp must have exactly nanosecond precision", ErrInvalidCommit)
	}
	parsed, err := time.Parse(timestampLayout, value)
	if err != nil || parsed.Location() != time.UTC || parsed.Format(timestampLayout) != value {
		return "", fmt.Errorf("%w: timestamp must be canonical UTC RFC 3339: %q", ErrInvalidCommit, value)
	}
	return Timestamp(value), nil
}

func (t Timestamp) Validate() error {
	_, err := ParseTimestamp(string(t))
	return err
}

// InitializeAction identifies the sole provenance action permitted on a
// parentless workspace-initialization commit.
func InitializeAction() artifact.TypeRef {
	return artifact.TypeRef{
		Group:   "operations.enbu.net",
		Version: "v1alpha1",
		Kind:    "Initialize",
	}
}

// PinnedInput records one immutable input used to produce a mutation. UID is
// explicit because a SealedRef deliberately contains only content identities.
type PinnedInput struct {
	Role   artifact.TypeRef   `cbor:"role" json:"role"`
	UID    artifact.UUID      `cbor:"uid" json:"uid"`
	Sealed artifact.SealedRef `cbor:"sealed" json:"sealed"`
}

func (i PinnedInput) Validate() error {
	if err := i.Role.Validate(); err != nil {
		return fmt.Errorf("%w: provenance input role: %v", ErrInvalidCommit, err)
	}
	if err := i.UID.Validate(); err != nil {
		return fmt.Errorf("%w: provenance input UID: %v", ErrInvalidCommit, err)
	}
	if err := i.Sealed.Validate(); err != nil {
		return fmt.Errorf("%w: provenance input sealed reference: %v", ErrInvalidCommit, err)
	}
	return nil
}

// MutationProvenance is a bounded, schema-neutral record of an immutable
// mutation. Action is a TypeRef so new operations don't require new Go node
// types. Plugin is present only when a pinned plugin package produced output.
type MutationProvenance struct {
	ID     artifact.UUID       `cbor:"id" json:"id"`
	Action artifact.TypeRef    `cbor:"action" json:"action"`
	Target artifact.UUID       `cbor:"target" json:"target"`
	Before *artifact.SealedRef `cbor:"before,omitempty" json:"before,omitempty"`
	After  *artifact.SealedRef `cbor:"after,omitempty" json:"after,omitempty"`
	Inputs []PinnedInput       `cbor:"inputs,omitempty" json:"inputs,omitempty"`
	Plugin digest.Digest       `cbor:"plugin,omitempty" json:"plugin,omitempty"`
}

func (p MutationProvenance) Validate() error {
	if err := p.ID.Validate(); err != nil {
		return fmt.Errorf("%w: provenance ID: %v", ErrInvalidCommit, err)
	}
	if err := p.Action.Validate(); err != nil {
		return fmt.Errorf("%w: provenance action: %v", ErrInvalidCommit, err)
	}
	if err := p.Target.Validate(); err != nil {
		return fmt.Errorf("%w: provenance target: %v", ErrInvalidCommit, err)
	}
	if p.Before == nil && p.After == nil {
		return fmt.Errorf("%w: provenance must pin a before or after revision", ErrInvalidCommit)
	}
	if p.Before != nil {
		if err := p.Before.Validate(); err != nil {
			return fmt.Errorf("%w: provenance before reference: %v", ErrInvalidCommit, err)
		}
	}
	if p.After != nil {
		if err := p.After.Validate(); err != nil {
			return fmt.Errorf("%w: provenance after reference: %v", ErrInvalidCommit, err)
		}
	}
	if p.Before != nil && p.After != nil && *p.Before == *p.After {
		return fmt.Errorf("%w: provenance before and after references are identical", ErrInvalidCommit)
	}
	if len(p.Inputs) > MaxInputsPerRecord {
		return fmt.Errorf("%w: provenance exceeds %d inputs", ErrInvalidCommit, MaxInputsPerRecord)
	}
	type inputIdentity struct {
		role string
		uid  artifact.UUID
	}
	seenInputs := make(map[inputIdentity]struct{}, len(p.Inputs))
	for index, input := range p.Inputs {
		if err := input.Validate(); err != nil {
			return fmt.Errorf("%w: inputs[%d]: %v", ErrInvalidCommit, index, err)
		}
		identity := inputIdentity{role: input.Role.String(), uid: input.UID}
		if _, exists := seenInputs[identity]; exists {
			return fmt.Errorf("%w: duplicate provenance input", ErrInvalidCommit)
		}
		seenInputs[identity] = struct{}{}
	}
	if p.Plugin != "" {
		if err := validateDigest(p.Plugin); err != nil {
			return fmt.Errorf("%w: provenance plugin digest: %v", ErrInvalidCommit, err)
		}
	}
	return nil
}

// Commit is the canonical signed plaintext placed inside an encrypted Commit
// envelope. It contains no payload plaintext or mutable identity attributes.
type Commit struct {
	APIVersion  string               `cbor:"apiVersion" json:"apiVersion"`
	Kind        string               `cbor:"kind" json:"kind"`
	WorkspaceID artifact.UUID        `cbor:"workspaceID" json:"workspaceID"`
	Root        artifact.SealedRef   `cbor:"root" json:"root"`
	Policy      artifact.SealedRef   `cbor:"policy" json:"policy"`
	Parents     []digest.Digest      `cbor:"parents,omitempty" json:"parents,omitempty"`
	Actor       string               `cbor:"actor" json:"actor"`
	DeviceID    artifact.UUID        `cbor:"deviceID" json:"deviceID"`
	OperationID artifact.UUID        `cbor:"operationID" json:"operationID"`
	Timestamp   Timestamp            `cbor:"timestamp" json:"timestamp"`
	Provenance  []MutationProvenance `cbor:"provenance" json:"provenance"`
}

func (c Commit) Validate() error {
	if c.APIVersion != APIVersion {
		return fmt.Errorf("%w: unsupported API version %q", ErrInvalidCommit, c.APIVersion)
	}
	if c.Kind != Kind {
		return fmt.Errorf("%w: unsupported kind %q", ErrInvalidCommit, c.Kind)
	}
	if err := c.WorkspaceID.Validate(); err != nil {
		return fmt.Errorf("%w: workspace ID: %v", ErrInvalidCommit, err)
	}
	if err := c.Root.Validate(); err != nil {
		return fmt.Errorf("%w: root reference: %v", ErrInvalidCommit, err)
	}
	if err := c.Policy.Validate(); err != nil {
		return fmt.Errorf("%w: policy reference: %v", ErrInvalidCommit, err)
	}
	if len(c.Parents) > MaxParents {
		return fmt.Errorf("%w: commit exceeds %d parents", ErrInvalidCommit, MaxParents)
	}
	seenParents := make(map[digest.Digest]struct{}, len(c.Parents))
	for index, parent := range c.Parents {
		if err := validateDigest(parent); err != nil {
			return fmt.Errorf("%w: parents[%d]: %v", ErrInvalidCommit, index, err)
		}
		if _, exists := seenParents[parent]; exists {
			return fmt.Errorf("%w: duplicate parent %q", ErrInvalidCommit, parent)
		}
		seenParents[parent] = struct{}{}
	}
	if err := validateActor(c.Actor); err != nil {
		return fmt.Errorf("%w: actor: %v", ErrInvalidCommit, err)
	}
	if err := c.DeviceID.Validate(); err != nil {
		return fmt.Errorf("%w: device ID: %v", ErrInvalidCommit, err)
	}
	if err := c.OperationID.Validate(); err != nil {
		return fmt.Errorf("%w: operation ID: %v", ErrInvalidCommit, err)
	}
	if err := c.Timestamp.Validate(); err != nil {
		return err
	}
	if len(c.Provenance) == 0 || len(c.Provenance) > MaxProvenanceRecords {
		return fmt.Errorf("%w: commit must have 1-%d provenance records", ErrInvalidCommit, MaxProvenanceRecords)
	}
	seenRecords := make(map[artifact.UUID]struct{}, len(c.Provenance))
	initializeCount := 0
	for index, record := range c.Provenance {
		if err := record.Validate(); err != nil {
			return fmt.Errorf("%w: provenance[%d]: %v", ErrInvalidCommit, index, err)
		}
		if _, exists := seenRecords[record.ID]; exists {
			return fmt.Errorf("%w: duplicate provenance ID %q", ErrInvalidCommit, record.ID)
		}
		seenRecords[record.ID] = struct{}{}
		if record.Action == InitializeAction() {
			initializeCount++
			if record.Before != nil || record.After == nil || len(record.Inputs) != 0 || record.Plugin != "" || *record.After != c.Root {
				return fmt.Errorf("%w: initialization provenance has invalid references", ErrInvalidCommit)
			}
		}
	}
	if len(c.Parents) == 0 {
		if len(c.Provenance) != 1 || initializeCount != 1 {
			return fmt.Errorf("%w: parentless commit must be workspace initialization", ErrInvalidCommit)
		}
	} else if initializeCount != 0 {
		return fmt.Errorf("%w: initialization commit must not have parents", ErrInvalidCommit)
	}
	return nil
}

// SignedCommit is the authenticated plaintext stored inside the encrypted
// commit envelope. Its embedded key is trusted only after AuthorEnrollment is
// checked by a caller-selected EnrollmentVerifier.
type SignedCommit struct {
	Commit           Commit            `cbor:"commit" json:"commit"`
	SigningKey       ed25519.PublicKey `cbor:"signingKey" json:"signingKey"`
	AuthorEnrollment []byte            `cbor:"authorEnrollment" json:"authorEnrollment"`
	Signature        []byte            `cbor:"signature" json:"signature"`
}

// Signer supports OS-protected or hardware-backed Ed25519 implementations
// without exposing private key bytes to this package.
type Signer interface {
	DeviceID() artifact.UUID
	SigningPublicKey() ed25519.PublicKey
	Sign([]byte) ([]byte, error)
}

func canonicalCommit(value Commit) Commit {
	canonical := value
	canonical.Parents = append([]digest.Digest(nil), value.Parents...)
	sort.Slice(canonical.Parents, func(i, j int) bool {
		return canonical.Parents[i].String() < canonical.Parents[j].String()
	})
	canonical.Provenance = append([]MutationProvenance(nil), value.Provenance...)
	for index := range canonical.Provenance {
		canonical.Provenance[index] = canonicalProvenance(canonical.Provenance[index])
	}
	sort.Slice(canonical.Provenance, func(i, j int) bool {
		return canonical.Provenance[i].ID < canonical.Provenance[j].ID
	})
	return canonical
}

func canonicalProvenance(value MutationProvenance) MutationProvenance {
	canonical := value
	canonical.Inputs = append([]PinnedInput(nil), value.Inputs...)
	sort.Slice(canonical.Inputs, func(i, j int) bool {
		if canonical.Inputs[i].Role.String() != canonical.Inputs[j].Role.String() {
			return canonical.Inputs[i].Role.String() < canonical.Inputs[j].Role.String()
		}
		if canonical.Inputs[i].UID != canonical.Inputs[j].UID {
			return canonical.Inputs[i].UID < canonical.Inputs[j].UID
		}
		return sealedRefLess(canonical.Inputs[i].Sealed, canonical.Inputs[j].Sealed)
	})
	return canonical
}

func sealedRefLess(left, right artifact.SealedRef) bool {
	if left.Revision != right.Revision {
		return left.Revision.String() < right.Revision.String()
	}
	if left.Material != right.Material {
		return left.Material.String() < right.Material.String()
	}
	return left.Grant.String() < right.Grant.String()
}

func cloneCommit(value Commit) Commit {
	cloned := value
	cloned.Parents = append([]digest.Digest(nil), value.Parents...)
	cloned.Provenance = append([]MutationProvenance(nil), value.Provenance...)
	for index := range cloned.Provenance {
		record := &cloned.Provenance[index]
		if record.Before != nil {
			before := *record.Before
			record.Before = &before
		}
		if record.After != nil {
			after := *record.After
			record.After = &after
		}
		record.Inputs = append([]PinnedInput(nil), record.Inputs...)
	}
	return cloned
}

func validateActor(value string) error {
	if value == "" || len(value) > MaxActorBytes || !utf8.ValidString(value) || !norm.NFC.IsNormalString(value) {
		return fmt.Errorf("must be non-empty NFC UTF-8 text of at most %d bytes", MaxActorBytes)
	}
	if strings.IndexFunc(value, func(r rune) bool { return r < 0x20 || r == 0x7f }) >= 0 {
		return errors.New("must not contain control characters")
	}
	return nil
}

func validateDigest(value digest.Digest) error {
	if err := value.Validate(); err != nil {
		return err
	}
	if value.Algorithm() != digest.SHA256 {
		return fmt.Errorf("digest algorithm %q is not sha256", value.Algorithm())
	}
	return nil
}

func publicKeysEqual(left, right ed25519.PublicKey) bool {
	return len(left) == ed25519.PublicKeySize && len(right) == ed25519.PublicKeySize && bytes.Equal(left, right)
}
