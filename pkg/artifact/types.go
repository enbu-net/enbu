// Package artifact defines enbu's encrypted artifact intermediate representation.
//
// The representation deliberately has only two node kinds: Resource and
// Collection. Schema-specific meaning belongs to TypeRef values and to trusted
// host code or sandboxed transforms, not to additional graph node types.
package artifact

import (
	"encoding/hex"
	"errors"
	"fmt"
	"mime"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/opencontainers/go-digest"
	"golang.org/x/text/unicode/norm"
)

const (
	// APIVersion is the only artifact wire version accepted by this package.
	APIVersion = "artifacts.enbu.net/v1alpha1"

	// ReservedNamespace is owned by the enbu host. Untrusted extensions must
	// not create TypeRefs or metadata keys in it or any of its subdomains.
	ReservedNamespace = "enbu.net"

	MaxMetadataBytes   = 256 * 1024
	MaxMetadataEntries = 4 * 1024
	MaxPayloads        = 1024
	MaxEdges           = 10_000
	MaxRevisionBytes   = 16 * 1024 * 1024
)

var (
	ErrInvalidArtifact   = errors.New("invalid artifact")
	ErrReservedNamespace = errors.New("reserved enbu namespace")

	qualifiedNamePartPattern = regexp.MustCompile(`^[A-Za-z0-9](?:[-A-Za-z0-9_.]*[A-Za-z0-9])?$`)
	labelValuePattern        = regexp.MustCompile(`^(?:[A-Za-z0-9](?:[-A-Za-z0-9_.]*[A-Za-z0-9])?)?$`)
	dnsLabelPattern          = regexp.MustCompile(`^[a-z0-9](?:[-a-z0-9]*[a-z0-9])?$`)
	versionPattern           = regexp.MustCompile(`^v[1-9][0-9]*(?:(?:alpha|beta)[1-9][0-9]*)?$`)
	kindPattern              = regexp.MustCompile(`^[A-Z][A-Za-z0-9]{0,62}$`)
	payloadNamePattern       = regexp.MustCompile(`^[A-Za-z0-9](?:[-A-Za-z0-9_.]*[A-Za-z0-9])?$`)
)

// Kind is a graph node kind. Schema-specific kinds are represented by TypeRef.
type Kind string

const (
	KindResource   Kind = "Resource"
	KindCollection Kind = "Collection"
)

// MemberRelation returns the host-owned relation used for Collection members.
func MemberRelation() TypeRef {
	return TypeRef{
		Group:   "relations.enbu.net",
		Version: "v1alpha1",
		Kind:    "Member",
	}
}

// UUID is a canonical, non-nil RFC 9562 UUID string.
//
// Only lowercase hyphenated values are accepted so a UUID has exactly one wire
// representation. Versions 1 through 8 using the RFC variant are supported.
type UUID string

func ParseUUID(value string) (UUID, error) {
	if len(value) != 36 || value[8] != '-' || value[13] != '-' || value[18] != '-' || value[23] != '-' {
		return "", fmt.Errorf("%w: UUID must use lowercase 8-4-4-4-12 form", ErrInvalidArtifact)
	}
	for i, r := range value {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			continue
		}
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return "", fmt.Errorf("%w: UUID contains non-canonical hexadecimal", ErrInvalidArtifact)
		}
	}

	raw, err := hex.DecodeString(strings.ReplaceAll(value, "-", ""))
	if err != nil {
		return "", fmt.Errorf("%w: decode UUID: %v", ErrInvalidArtifact, err)
	}
	allZero := true
	for _, b := range raw {
		allZero = allZero && b == 0
	}
	if allZero {
		return "", fmt.Errorf("%w: nil UUID is not allowed", ErrInvalidArtifact)
	}
	version := raw[6] >> 4
	if version < 1 || version > 8 {
		return "", fmt.Errorf("%w: unsupported UUID version %d", ErrInvalidArtifact, version)
	}
	if raw[8]&0xc0 != 0x80 {
		return "", fmt.Errorf("%w: UUID does not use the RFC variant", ErrInvalidArtifact)
	}

	return UUID(value), nil
}

func (u UUID) Validate() error {
	_, err := ParseUUID(string(u))
	return err
}

// TypeRef identifies the schema or relation semantics of an artifact value.
type TypeRef struct {
	Group   string `cbor:"group" json:"group"`
	Version string `cbor:"version" json:"version"`
	Kind    string `cbor:"kind" json:"kind"`
}

func ParseTypeRef(value string) (TypeRef, error) {
	parts := strings.Split(value, "/")
	if len(parts) != 3 {
		return TypeRef{}, fmt.Errorf("%w: type reference must use group/version/kind form", ErrInvalidArtifact)
	}
	ref := TypeRef{Group: parts[0], Version: parts[1], Kind: parts[2]}
	if err := ref.Validate(); err != nil {
		return TypeRef{}, err
	}
	return ref, nil
}

func (r TypeRef) String() string {
	return r.Group + "/" + r.Version + "/" + r.Kind
}

func (r TypeRef) Validate() error {
	if err := validateDNSSubdomain(r.Group); err != nil {
		return fmt.Errorf("%w: type group: %v", ErrInvalidArtifact, err)
	}
	if !versionPattern.MatchString(r.Version) {
		return fmt.Errorf("%w: invalid type version %q", ErrInvalidArtifact, r.Version)
	}
	if !kindPattern.MatchString(r.Kind) {
		return fmt.Errorf("%w: invalid type kind %q", ErrInvalidArtifact, r.Kind)
	}
	return nil
}

// ValidateExtension rejects TypeRefs reserved for the enbu host.
func (r TypeRef) ValidateExtension() error {
	if err := r.Validate(); err != nil {
		return err
	}
	if IsReservedNamespace(r.Group) {
		return fmt.Errorf("%w: type group %q", ErrReservedNamespace, r.Group)
	}
	return nil
}

// Metadata contains encrypted, queryable attributes. It is not an access-control
// boundary; graph position, labels, and annotations never imply authorization.
type Metadata struct {
	Name        string            `cbor:"name" json:"name"`
	Labels      map[string]string `cbor:"labels,omitempty" json:"labels,omitempty"`
	Annotations map[string]string `cbor:"annotations,omitempty" json:"annotations,omitempty"`
}

func (m Metadata) Validate() error {
	if err := validateDisplayName(m.Name); err != nil {
		return fmt.Errorf("%w: metadata name: %v", ErrInvalidArtifact, err)
	}
	if len(m.Labels)+len(m.Annotations) > MaxMetadataEntries {
		return fmt.Errorf("%w: metadata exceeds %d entries", ErrInvalidArtifact, MaxMetadataEntries)
	}

	for key, value := range m.Labels {
		if err := validateQualifiedName(key); err != nil {
			return fmt.Errorf("%w: label %q: %v", ErrInvalidArtifact, key, err)
		}
		if len(value) > 63 || !labelValuePattern.MatchString(value) {
			return fmt.Errorf("%w: invalid label value for %q", ErrInvalidArtifact, key)
		}
	}
	for key, value := range m.Annotations {
		if err := validateQualifiedName(key); err != nil {
			return fmt.Errorf("%w: annotation %q: %v", ErrInvalidArtifact, key, err)
		}
		if !utf8.ValidString(value) || strings.ContainsRune(value, '\x00') {
			return fmt.Errorf("%w: annotation %q is not valid UTF-8 text", ErrInvalidArtifact, key)
		}
		if !norm.NFC.IsNormalString(value) {
			return fmt.Errorf("%w: annotation %q is not NFC", ErrInvalidArtifact, key)
		}
	}
	encoded, err := MarshalCanonical(struct {
		Labels      map[string]string `cbor:"labels,omitempty"`
		Annotations map[string]string `cbor:"annotations,omitempty"`
	}{Labels: m.Labels, Annotations: m.Annotations})
	if err != nil {
		return fmt.Errorf("%w: encode metadata: %v", ErrInvalidArtifact, err)
	}
	if len(encoded) > MaxMetadataBytes {
		return fmt.Errorf("%w: metadata exceeds %d bytes", ErrInvalidArtifact, MaxMetadataBytes)
	}
	return nil
}

// ValidateExtension additionally prevents an untrusted extension from creating
// host-owned metadata. Existing host metadata can still be read by an extension.
func (m Metadata) ValidateExtension() error {
	if err := m.Validate(); err != nil {
		return err
	}
	for key := range m.Labels {
		if IsReservedMetadataKey(key) {
			return fmt.Errorf("%w: label %q", ErrReservedNamespace, key)
		}
	}
	for key := range m.Annotations {
		if IsReservedMetadataKey(key) {
			return fmt.Errorf("%w: annotation %q", ErrReservedNamespace, key)
		}
	}
	return nil
}

func IsReservedNamespace(namespace string) bool {
	return namespace == ReservedNamespace || strings.HasSuffix(namespace, "."+ReservedNamespace)
}

func IsReservedMetadataKey(key string) bool {
	prefix, _, ok := strings.Cut(key, "/")
	return ok && IsReservedNamespace(prefix)
}

// PayloadRef describes a named plaintext stream. The surrounding encrypted
// material manifest maps this logical reference to ciphertext chunks. Digest
// always uses SHA-256.
type PayloadRef struct {
	Name      string        `cbor:"name" json:"name"`
	MediaType string        `cbor:"mediaType" json:"mediaType"`
	Digest    digest.Digest `cbor:"digest" json:"digest"`
	Size      int64         `cbor:"size" json:"size"`
}

func (p PayloadRef) Validate() error {
	if len(p.Name) == 0 || len(p.Name) > 253 || !payloadNamePattern.MatchString(p.Name) {
		return fmt.Errorf("%w: invalid payload name %q", ErrInvalidArtifact, p.Name)
	}
	if p.MediaType == "" {
		return fmt.Errorf("%w: payload %q has empty media type", ErrInvalidArtifact, p.Name)
	}
	if _, _, err := mime.ParseMediaType(p.MediaType); err != nil {
		return fmt.Errorf("%w: payload %q media type: %v", ErrInvalidArtifact, p.Name, err)
	}
	if err := validateDigest(p.Digest); err != nil {
		return fmt.Errorf("%w: payload %q digest: %v", ErrInvalidArtifact, p.Name, err)
	}
	if p.Size < 0 {
		return fmt.Errorf("%w: payload %q has negative size", ErrInvalidArtifact, p.Name)
	}
	return nil
}

// EdgeStrength determines whether an edge pins an immutable revision or merely
// relates one stable UID to another. Only pinned edges participate in the DAG.
type EdgeStrength string

const (
	EdgePinned  EdgeStrength = "pinned"
	EdgeLogical EdgeStrength = "logical"
)

type Edge struct {
	ID       UUID         `cbor:"id" json:"id"`
	Name     string       `cbor:"name" json:"name"`
	Relation TypeRef      `cbor:"relation" json:"relation"`
	Strength EdgeStrength `cbor:"strength" json:"strength"`
	Target   UUID         `cbor:"target" json:"target"`
	Pinned   *SealedRef   `cbor:"pinned,omitempty" json:"pinned,omitempty"`
}

func (e Edge) Validate() error {
	if err := e.ID.Validate(); err != nil {
		return fmt.Errorf("%w: edge ID: %v", ErrInvalidArtifact, err)
	}
	if err := validateDisplayName(e.Name); err != nil {
		return fmt.Errorf("%w: edge name: %v", ErrInvalidArtifact, err)
	}
	if err := e.Relation.Validate(); err != nil {
		return fmt.Errorf("%w: edge relation: %v", ErrInvalidArtifact, err)
	}
	if err := e.Target.Validate(); err != nil {
		return fmt.Errorf("%w: edge target: %v", ErrInvalidArtifact, err)
	}
	switch e.Strength {
	case EdgePinned:
		if e.Pinned == nil {
			return fmt.Errorf("%w: pinned edge %q has no sealed reference", ErrInvalidArtifact, e.Name)
		}
		if err := e.Pinned.Validate(); err != nil {
			return fmt.Errorf("%w: pinned edge %q: %v", ErrInvalidArtifact, e.Name, err)
		}
	case EdgeLogical:
		if e.Pinned != nil {
			return fmt.Errorf("%w: logical edge %q must not pin a revision", ErrInvalidArtifact, e.Name)
		}
	default:
		return fmt.Errorf("%w: edge %q has invalid strength %q", ErrInvalidArtifact, e.Name, e.Strength)
	}
	return nil
}

// SealedRef binds an encrypted revision to its material and access grant.
type SealedRef struct {
	Revision digest.Digest `cbor:"revision" json:"revision"`
	Material digest.Digest `cbor:"material" json:"material"`
	Grant    digest.Digest `cbor:"grant" json:"grant"`
}

func (r SealedRef) Validate() error {
	if err := validateDigest(r.Revision); err != nil {
		return fmt.Errorf("%w: revision digest: %v", ErrInvalidArtifact, err)
	}
	if err := validateDigest(r.Material); err != nil {
		return fmt.Errorf("%w: material digest: %v", ErrInvalidArtifact, err)
	}
	if err := validateDigest(r.Grant); err != nil {
		return fmt.Errorf("%w: grant digest: %v", ErrInvalidArtifact, err)
	}
	return nil
}

type Revision struct {
	APIVersion string       `cbor:"apiVersion" json:"apiVersion"`
	Kind       Kind         `cbor:"kind" json:"kind"`
	UID        UUID         `cbor:"uid" json:"uid"`
	Schema     TypeRef      `cbor:"schema" json:"schema"`
	Metadata   Metadata     `cbor:"metadata" json:"metadata"`
	Payloads   []PayloadRef `cbor:"payloads,omitempty" json:"payloads,omitempty"`
	Edges      []Edge       `cbor:"edges,omitempty" json:"edges,omitempty"`
}

func (r Revision) Validate() error {
	if r.APIVersion != APIVersion {
		return fmt.Errorf("%w: unsupported API version %q", ErrInvalidArtifact, r.APIVersion)
	}
	if r.Kind != KindResource && r.Kind != KindCollection {
		return fmt.Errorf("%w: unsupported node kind %q", ErrInvalidArtifact, r.Kind)
	}
	if err := r.UID.Validate(); err != nil {
		return fmt.Errorf("%w: revision UID: %v", ErrInvalidArtifact, err)
	}
	if err := r.Schema.Validate(); err != nil {
		return fmt.Errorf("%w: schema: %v", ErrInvalidArtifact, err)
	}
	if err := r.Metadata.Validate(); err != nil {
		return err
	}
	if len(r.Payloads) > MaxPayloads {
		return fmt.Errorf("%w: revision exceeds %d payloads", ErrInvalidArtifact, MaxPayloads)
	}
	if len(r.Edges) > MaxEdges {
		return fmt.Errorf("%w: revision exceeds %d edges", ErrInvalidArtifact, MaxEdges)
	}
	if r.Kind == KindResource && len(r.Payloads) == 0 {
		return fmt.Errorf("%w: Resource requires at least one payload", ErrInvalidArtifact)
	}
	if r.Kind == KindCollection && len(r.Payloads) != 0 {
		return fmt.Errorf("%w: Collection must not contain payloads", ErrInvalidArtifact)
	}

	payloadNames := make(map[string]struct{}, len(r.Payloads))
	for i, payload := range r.Payloads {
		if err := payload.Validate(); err != nil {
			return fmt.Errorf("%w: payloads[%d]: %v", ErrInvalidArtifact, i, err)
		}
		if _, exists := payloadNames[payload.Name]; exists {
			return fmt.Errorf("%w: duplicate payload name %q", ErrInvalidArtifact, payload.Name)
		}
		payloadNames[payload.Name] = struct{}{}
	}
	edgeIDs := make(map[UUID]struct{}, len(r.Edges))
	edgeNames := make(map[string]struct{}, len(r.Edges))
	for i, edge := range r.Edges {
		if err := edge.Validate(); err != nil {
			return fmt.Errorf("%w: edges[%d]: %v", ErrInvalidArtifact, i, err)
		}
		if _, exists := edgeIDs[edge.ID]; exists {
			return fmt.Errorf("%w: duplicate edge ID %q", ErrInvalidArtifact, edge.ID)
		}
		edgeIDs[edge.ID] = struct{}{}
		if _, exists := edgeNames[edge.Name]; exists {
			return fmt.Errorf("%w: duplicate edge name %q", ErrInvalidArtifact, edge.Name)
		}
		edgeNames[edge.Name] = struct{}{}
		if edge.Relation == MemberRelation() && (r.Kind != KindCollection || edge.Strength != EdgePinned) {
			return fmt.Errorf("%w: Member edge %q must be pinned from a Collection", ErrInvalidArtifact, edge.Name)
		}
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

func validateDisplayName(value string) error {
	if value == "" {
		return errors.New("must not be empty")
	}
	if len(value) > 253 {
		return errors.New("must be at most 253 bytes")
	}
	if !utf8.ValidString(value) {
		return errors.New("must be valid UTF-8")
	}
	if !norm.NFC.IsNormalString(value) {
		return errors.New("must be NFC")
	}
	for _, r := range value {
		if r < 0x20 || r == 0x7f || r == '/' || r == '\\' {
			return errors.New("must not contain control characters or path separators")
		}
	}
	return nil
}

func validateQualifiedName(value string) error {
	prefix, name, qualified := strings.Cut(value, "/")
	if !qualified {
		name = prefix
		prefix = ""
	}
	if prefix != "" {
		if err := validateDNSSubdomain(prefix); err != nil {
			return fmt.Errorf("invalid DNS prefix: %w", err)
		}
	}
	if len(name) == 0 || len(name) > 63 || !qualifiedNamePartPattern.MatchString(name) {
		return errors.New("name must be a valid 1-63 byte qualified name")
	}
	return nil
}

func validateDNSSubdomain(value string) error {
	if len(value) == 0 || len(value) > 253 {
		return errors.New("must be 1-253 bytes")
	}
	for _, label := range strings.Split(value, ".") {
		if len(label) == 0 || len(label) > 63 || !dnsLabelPattern.MatchString(label) {
			return fmt.Errorf("invalid DNS label %q", label)
		}
	}
	return nil
}
