package plugin

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/enbu-net/enbu/pkg/artifact"
	"github.com/opencontainers/go-digest"
	"golang.org/x/text/unicode/norm"
)

const (
	APIVersion     = "plugins.enbu.net/v1alpha1"
	PackageKind    = "PluginPackage"
	TrustGrantKind = "PluginTrustGrant"

	MaxOutputNamespaces = 64
	MaxPackageBytes     = MaxModuleBytes + 128*1024
	MaxTrustGrantBytes  = 128 * 1024

	packageSigningDomain = "enbu.net/plugin-package/v1\x00"
)

var (
	ErrInvalidPackage    = errors.New("plugin: invalid package")
	ErrInvalidTrustGrant = errors.New("plugin: invalid trust grant")
	ErrUntrustedPackage  = errors.New("plugin: untrusted package")
)

// TypeNamespace is the smallest output authority a plugin can request. It
// grants kinds only in one exact DNS group and one exact schema version; it is
// deliberately not a wildcard or subdomain prefix.
type TypeNamespace struct {
	Group   string `cbor:"group" json:"group"`
	Version string `cbor:"version" json:"version"`
}

func (namespace TypeNamespace) String() string {
	return namespace.Group + "/" + namespace.Version
}

func (namespace TypeNamespace) Validate() error {
	if len(namespace.Version) > 32 {
		return fmt.Errorf("plugin: output namespace version is too long")
	}
	// TypeRef owns the canonical DNS and version grammar. A placeholder kind is
	// used only to validate the namespace components.
	ref := artifact.TypeRef{Group: namespace.Group, Version: namespace.Version, Kind: "Output"}
	if err := ref.ValidateExtension(); err != nil {
		return fmt.Errorf("plugin: invalid output namespace %q: %w", namespace.String(), err)
	}
	// A single DNS label (for example "com") is not an identity a plugin can
	// reasonably control and would grant an overbroad schema namespace.
	if !strings.Contains(namespace.Group, ".") {
		return fmt.Errorf("plugin: output namespace %q is overbroad", namespace.String())
	}
	return nil
}

func (namespace TypeNamespace) Contains(ref artifact.TypeRef) bool {
	return namespace.Group == ref.Group && namespace.Version == ref.Version
}

// Package is the complete signed plugin package. Signature authenticates the
// claims, while ModuleDigest authenticates Module. PackageDigest additionally
// pins the exact canonical package, including the signature and module bytes.
type Package struct {
	APIVersion       string          `cbor:"apiVersion" json:"apiVersion"`
	Kind             string          `cbor:"kind" json:"kind"`
	Module           []byte          `cbor:"module" json:"module"`
	ModuleDigest     digest.Digest   `cbor:"moduleDigest" json:"moduleDigest"`
	Issuer           string          `cbor:"issuer" json:"issuer"`
	Subject          string          `cbor:"subject" json:"subject"`
	OutputNamespaces []TypeNamespace `cbor:"outputNamespaces" json:"outputNamespaces"`
	Signature        []byte          `cbor:"signature" json:"signature"`
}

type packageClaims struct {
	APIVersion       string          `cbor:"apiVersion"`
	Kind             string          `cbor:"kind"`
	ModuleDigest     digest.Digest   `cbor:"moduleDigest"`
	Issuer           string          `cbor:"issuer"`
	Subject          string          `cbor:"subject"`
	OutputNamespaces []TypeNamespace `cbor:"outputNamespaces"`
}

// NewPackage constructs canonical unsigned package claims. SignPackage must be
// called before the package can be trusted or executed.
func NewPackage(module []byte, issuer, subject string, outputs []TypeNamespace) (Package, error) {
	canonicalOutputs := cloneNamespaces(outputs)
	sort.Slice(canonicalOutputs, func(i, j int) bool {
		return canonicalOutputs[i].String() < canonicalOutputs[j].String()
	})
	pkg := Package{
		APIVersion:       APIVersion,
		Kind:             PackageKind,
		Module:           append([]byte(nil), module...),
		ModuleDigest:     digest.FromBytes(module),
		Issuer:           issuer,
		Subject:          subject,
		OutputNamespaces: canonicalOutputs,
	}
	if err := validatePackageClaims(pkg); err != nil {
		return Package{}, err
	}
	return pkg, nil
}

// SignPackage returns a copy signed over every package claim. Module itself is
// bound through ModuleDigest and is also included in the final package digest.
func SignPackage(pkg Package, privateKey ed25519.PrivateKey) (Package, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return Package{}, fmt.Errorf("%w: signing key", ErrInvalidPackage)
	}
	pkg.Signature = nil
	if err := validatePackageClaims(pkg); err != nil {
		return Package{}, err
	}
	message, err := packageSigningMessage(pkg)
	if err != nil {
		return Package{}, err
	}
	pkg.Signature = ed25519.Sign(privateKey, message)
	return clonePackage(pkg), nil
}

// PackageDigest returns the SHA-256 digest of the complete canonical package.
func PackageDigest(pkg Package) (digest.Digest, error) {
	encoded, err := EncodePackage(pkg)
	if err != nil {
		return "", err
	}
	return digest.FromBytes(encoded), nil
}

// EncodePackage returns the only accepted wire representation of a signed
// package.
func EncodePackage(pkg Package) ([]byte, error) {
	if err := validatePackage(pkg); err != nil {
		return nil, err
	}
	encoded, err := artifact.MarshalCanonical(pkg)
	if err != nil {
		return nil, fmt.Errorf("%w: encode package: %w", ErrInvalidPackage, err)
	}
	if len(encoded) > MaxPackageBytes {
		return nil, fmt.Errorf("%w: encoded package exceeds %d bytes", ErrInvalidPackage, MaxPackageBytes)
	}
	return encoded, nil
}

// DecodePackage accepts strict, canonical CBOR only and applies all structural
// bounds before the package reaches signature verification.
func DecodePackage(encoded []byte) (Package, error) {
	if len(encoded) == 0 || len(encoded) > MaxPackageBytes {
		return Package{}, fmt.Errorf("%w: encoded package size", ErrInvalidPackage)
	}
	var pkg Package
	if err := artifact.UnmarshalStrict(encoded, &pkg); err != nil {
		return Package{}, fmt.Errorf("%w: decode package: %w", ErrInvalidPackage, err)
	}
	canonical, err := EncodePackage(pkg)
	if err != nil {
		return Package{}, err
	}
	if !bytes.Equal(encoded, canonical) {
		return Package{}, fmt.Errorf("%w: %w", ErrInvalidPackage, artifact.ErrNonCanonicalEncoding)
	}
	return clonePackage(pkg), nil
}

type TrustScope string

const (
	TrustScopeLocal        TrustScope = "local"
	TrustScopeOrganization TrustScope = "organization"
)

// TrustGrant is trusted local state or an organization-managed trust record.
// A repository may name a package digest, but it cannot construct this value as
// trusted state. Callers are responsible for authenticating organization grants
// before passing them to VerifyPackage.
type TrustGrant struct {
	APIVersion              string            `cbor:"apiVersion" json:"apiVersion"`
	Kind                    string            `cbor:"kind" json:"kind"`
	Scope                   TrustScope        `cbor:"scope" json:"scope"`
	PackageDigest           digest.Digest     `cbor:"packageDigest" json:"packageDigest"`
	Issuer                  string            `cbor:"issuer" json:"issuer"`
	Subject                 string            `cbor:"subject" json:"subject"`
	AllowedOutputNamespaces []TypeNamespace   `cbor:"allowedOutputNamespaces" json:"allowedOutputNamespaces"`
	SigningKey              ed25519.PublicKey `cbor:"signingKey" json:"signingKey"`
}

// NewTrustGrant creates a canonical, least-privilege trust grant for one exact
// signed package. Its allowed namespaces are intentionally explicit.
func NewTrustGrant(
	scope TrustScope,
	packageDigest digest.Digest,
	issuer, subject string,
	outputs []TypeNamespace,
	publicKey ed25519.PublicKey,
) (TrustGrant, error) {
	canonicalOutputs := cloneNamespaces(outputs)
	sort.Slice(canonicalOutputs, func(i, j int) bool {
		return canonicalOutputs[i].String() < canonicalOutputs[j].String()
	})
	grant := TrustGrant{
		APIVersion:              APIVersion,
		Kind:                    TrustGrantKind,
		Scope:                   scope,
		PackageDigest:           packageDigest,
		Issuer:                  issuer,
		Subject:                 subject,
		AllowedOutputNamespaces: canonicalOutputs,
		SigningKey:              append(ed25519.PublicKey(nil), publicKey...),
	}
	if err := grant.Validate(); err != nil {
		return TrustGrant{}, err
	}
	return grant, nil
}

func (grant TrustGrant) Validate() error {
	if grant.APIVersion != APIVersion {
		return fmt.Errorf("%w: unsupported API version %q", ErrInvalidTrustGrant, grant.APIVersion)
	}
	if grant.Kind != TrustGrantKind {
		return fmt.Errorf("%w: unsupported kind %q", ErrInvalidTrustGrant, grant.Kind)
	}
	if grant.Scope != TrustScopeLocal && grant.Scope != TrustScopeOrganization {
		return fmt.Errorf("%w: scope %q", ErrInvalidTrustGrant, grant.Scope)
	}
	if err := validateSHA256(grant.PackageDigest); err != nil {
		return fmt.Errorf("%w: package digest: %v", ErrInvalidTrustGrant, err)
	}
	if err := validateIdentity("issuer", grant.Issuer); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidTrustGrant, err)
	}
	if err := validateIdentity("subject", grant.Subject); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidTrustGrant, err)
	}
	if len(grant.SigningKey) != ed25519.PublicKeySize {
		return fmt.Errorf("%w: signing key", ErrInvalidTrustGrant)
	}
	if err := validateNamespaces(grant.AllowedOutputNamespaces); err != nil {
		return fmt.Errorf("%w: allowed outputs: %w", ErrInvalidTrustGrant, err)
	}
	return nil
}

func EncodeTrustGrant(grant TrustGrant) ([]byte, error) {
	if err := grant.Validate(); err != nil {
		return nil, err
	}
	encoded, err := artifact.MarshalCanonical(grant)
	if err != nil {
		return nil, fmt.Errorf("%w: encode grant: %w", ErrInvalidTrustGrant, err)
	}
	if len(encoded) > MaxTrustGrantBytes {
		return nil, fmt.Errorf("%w: encoded grant exceeds %d bytes", ErrInvalidTrustGrant, MaxTrustGrantBytes)
	}
	return encoded, nil
}

func DecodeTrustGrant(encoded []byte) (TrustGrant, error) {
	if len(encoded) == 0 || len(encoded) > MaxTrustGrantBytes {
		return TrustGrant{}, fmt.Errorf("%w: encoded grant size", ErrInvalidTrustGrant)
	}
	var grant TrustGrant
	if err := artifact.UnmarshalStrict(encoded, &grant); err != nil {
		return TrustGrant{}, fmt.Errorf("%w: decode grant: %w", ErrInvalidTrustGrant, err)
	}
	canonical, err := EncodeTrustGrant(grant)
	if err != nil {
		return TrustGrant{}, err
	}
	if !bytes.Equal(encoded, canonical) {
		return TrustGrant{}, fmt.Errorf("%w: %w", ErrInvalidTrustGrant, artifact.ErrNonCanonicalEncoding)
	}
	grant.SigningKey = append(ed25519.PublicKey(nil), grant.SigningKey...)
	grant.AllowedOutputNamespaces = cloneNamespaces(grant.AllowedOutputNamespaces)
	return grant, nil
}

// VerifiedPackage is an immutable capability produced only after both package
// authentication and an exact trust-grant match. Its private module bytes stop
// callers from bypassing verification when invoking Host.Execute.
type VerifiedPackage struct {
	module           []byte
	digest           digest.Digest
	moduleDigest     digest.Digest
	issuer           string
	subject          string
	outputNamespaces []TypeNamespace
}

func (pkg VerifiedPackage) Digest() digest.Digest       { return pkg.digest }
func (pkg VerifiedPackage) ModuleDigest() digest.Digest { return pkg.moduleDigest }
func (pkg VerifiedPackage) Issuer() string              { return pkg.issuer }
func (pkg VerifiedPackage) Subject() string             { return pkg.subject }
func (pkg VerifiedPackage) OutputNamespaces() []TypeNamespace {
	return cloneNamespaces(pkg.outputNamespaces)
}

// VerifyPackage requires both a valid package signature and a separately
// provisioned trust grant. The package and grant must match exactly, including
// issuer, subject, package digest, signing key, and output namespaces.
func VerifyPackage(pkg Package, grant TrustGrant) (VerifiedPackage, error) {
	if err := grant.Validate(); err != nil {
		return VerifiedPackage{}, err
	}
	if err := validatePackage(pkg); err != nil {
		return VerifiedPackage{}, err
	}
	message, err := packageSigningMessage(pkg)
	if err != nil {
		return VerifiedPackage{}, err
	}
	if !ed25519.Verify(grant.SigningKey, message, pkg.Signature) {
		return VerifiedPackage{}, fmt.Errorf("%w: package signature", ErrInvalidPackage)
	}
	packageDigest, err := PackageDigest(pkg)
	if err != nil {
		return VerifiedPackage{}, err
	}
	if packageDigest != grant.PackageDigest {
		return VerifiedPackage{}, fmt.Errorf("%w: package digest", ErrUntrustedPackage)
	}
	if pkg.Issuer != grant.Issuer || pkg.Subject != grant.Subject {
		return VerifiedPackage{}, fmt.Errorf("%w: issuer or subject", ErrUntrustedPackage)
	}
	if !equalNamespaces(pkg.OutputNamespaces, grant.AllowedOutputNamespaces) {
		return VerifiedPackage{}, fmt.Errorf("%w: output namespaces", ErrUntrustedPackage)
	}
	return VerifiedPackage{
		module:           append([]byte(nil), pkg.Module...),
		digest:           packageDigest,
		moduleDigest:     pkg.ModuleDigest,
		issuer:           pkg.Issuer,
		subject:          pkg.Subject,
		outputNamespaces: cloneNamespaces(pkg.OutputNamespaces),
	}, nil
}

func validatePackage(pkg Package) error {
	if err := validatePackageClaims(pkg); err != nil {
		return err
	}
	if len(pkg.Signature) != ed25519.SignatureSize {
		return fmt.Errorf("%w: signature", ErrInvalidPackage)
	}
	return nil
}

func validatePackageClaims(pkg Package) error {
	if pkg.APIVersion != APIVersion {
		return fmt.Errorf("%w: unsupported API version %q", ErrInvalidPackage, pkg.APIVersion)
	}
	if pkg.Kind != PackageKind {
		return fmt.Errorf("%w: unsupported kind %q", ErrInvalidPackage, pkg.Kind)
	}
	if len(pkg.Module) == 0 || len(pkg.Module) > MaxModuleBytes || !bytesHasWasmHeader(pkg.Module) {
		return fmt.Errorf("%w: module", ErrInvalidPackage)
	}
	if err := validateSHA256(pkg.ModuleDigest); err != nil || pkg.ModuleDigest != digest.FromBytes(pkg.Module) {
		return fmt.Errorf("%w: module digest", ErrInvalidPackage)
	}
	if err := validateIdentity("issuer", pkg.Issuer); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidPackage, err)
	}
	if err := validateIdentity("subject", pkg.Subject); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidPackage, err)
	}
	if err := validateNamespaces(pkg.OutputNamespaces); err != nil {
		return fmt.Errorf("%w: outputs: %w", ErrInvalidPackage, err)
	}
	return nil
}

func packageSigningMessage(pkg Package) ([]byte, error) {
	claims := packageClaims{
		APIVersion:       pkg.APIVersion,
		Kind:             pkg.Kind,
		ModuleDigest:     pkg.ModuleDigest,
		Issuer:           pkg.Issuer,
		Subject:          pkg.Subject,
		OutputNamespaces: pkg.OutputNamespaces,
	}
	encoded, err := artifact.MarshalCanonical(claims)
	if err != nil {
		return nil, fmt.Errorf("%w: encode claims: %w", ErrInvalidPackage, err)
	}
	return append([]byte(packageSigningDomain), encoded...), nil
}

func validateNamespaces(namespaces []TypeNamespace) error {
	if len(namespaces) == 0 || len(namespaces) > MaxOutputNamespaces {
		return fmt.Errorf("must contain 1-%d namespaces", MaxOutputNamespaces)
	}
	previous := ""
	for index, namespace := range namespaces {
		if err := namespace.Validate(); err != nil {
			return fmt.Errorf("namespace[%d]: %w", index, err)
		}
		identity := namespace.String()
		if identity == previous {
			return fmt.Errorf("duplicate namespace %q", identity)
		}
		if previous > identity {
			return errors.New("namespaces are not in canonical order")
		}
		previous = identity
	}
	return nil
}

func validateIdentity(field, value string) error {
	if value == "" || len(value) > 253 || !utf8.ValidString(value) || !norm.NFC.IsNormalString(value) {
		return fmt.Errorf("%s must be non-empty NFC UTF-8 text of at most 253 bytes", field)
	}
	if strings.IndexFunc(value, func(character rune) bool {
		return character < 0x20 || character == 0x7f
	}) >= 0 {
		return fmt.Errorf("%s must not contain control characters", field)
	}
	return nil
}

func validateSHA256(value digest.Digest) error {
	if err := value.Validate(); err != nil {
		return err
	}
	if value.Algorithm() != digest.SHA256 {
		return fmt.Errorf("digest algorithm %q is not sha256", value.Algorithm())
	}
	return nil
}

func equalNamespaces(left, right []TypeNamespace) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func cloneNamespaces(namespaces []TypeNamespace) []TypeNamespace {
	return append([]TypeNamespace(nil), namespaces...)
}

func clonePackage(pkg Package) Package {
	pkg.Module = append([]byte(nil), pkg.Module...)
	pkg.OutputNamespaces = cloneNamespaces(pkg.OutputNamespaces)
	pkg.Signature = append([]byte(nil), pkg.Signature...)
	return pkg
}
