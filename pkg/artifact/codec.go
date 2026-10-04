package artifact

import (
	"bytes"
	"errors"
	"fmt"
	"sort"
	"unicode/utf8"

	"github.com/fxamacker/cbor/v2"
	"github.com/opencontainers/go-digest"
	"golang.org/x/text/unicode/norm"
)

var (
	ErrNonCanonicalEncoding = errors.New("non-canonical artifact encoding")

	canonicalEncMode = mustEncodingMode()
	strictDecMode    = mustDecodingMode()
)

func mustEncodingMode() cbor.EncMode {
	mode, err := cbor.CoreDetEncOptions().EncMode()
	if err != nil {
		panic(fmt.Sprintf("create deterministic CBOR encoder: %v", err))
	}
	return mode
}

func mustDecodingMode() cbor.DecMode {
	mode, err := (cbor.DecOptions{
		DupMapKey:         cbor.DupMapKeyEnforcedAPF,
		IndefLength:       cbor.IndefLengthForbidden,
		TagsMd:            cbor.TagsForbidden,
		UTF8:              cbor.UTF8RejectInvalid,
		ExtraReturnErrors: cbor.ExtraDecErrorUnknownField,
		MaxNestedLevels:   32,
		MaxArrayElements:  MaxPayloads,
		MaxMapPairs:       MaxMetadataEntries,
	}).DecMode()
	if err != nil {
		panic(fmt.Sprintf("create strict CBOR decoder: %v", err))
	}
	return mode
}

// Validate raw values before typed decoding, which can silently accept null as
// a zero value. Decoder limits bound both traversals.
func unmarshalStrict(data []byte, destination any) error {
	var wire any
	if err := strictDecMode.Unmarshal(data, &wire); err != nil {
		return fmt.Errorf("decode artifact CBOR: %w", err)
	}
	if err := validateWireValue(wire); err != nil {
		return err
	}
	if err := strictDecMode.Unmarshal(data, destination); err != nil {
		return fmt.Errorf("decode artifact CBOR: %w", err)
	}
	return nil
}

// EncodeArtifact returns the sole canonical wire representation of artifact.
// Payloads are ordered by name without mutating the caller.
func EncodeArtifact(artifact Artifact) ([]byte, error) {
	if err := artifact.Validate(); err != nil {
		return nil, err
	}
	canonical := canonicalArtifact(artifact)
	data, err := canonicalEncMode.Marshal(canonical)
	if err != nil {
		return nil, fmt.Errorf("encode artifact: %w", err)
	}
	if len(data) > MaxArtifactBytes {
		return nil, fmt.Errorf("%w: artifact exceeds %d encoded bytes", ErrInvalidArtifact, MaxArtifactBytes)
	}
	return data, nil
}

// DecodeArtifact accepts only the exact canonical representation emitted by
// EncodeArtifact. This prevents alternate encodings from acquiring the same
// semantic meaning while carrying a different content digest.
func DecodeArtifact(data []byte) (Artifact, error) {
	if len(data) > MaxArtifactBytes {
		return Artifact{}, fmt.Errorf("%w: artifact exceeds %d encoded bytes", ErrInvalidArtifact, MaxArtifactBytes)
	}
	var artifact Artifact
	if err := unmarshalStrict(data, &artifact); err != nil {
		return Artifact{}, err
	}
	canonical, err := EncodeArtifact(artifact)
	if err != nil {
		return Artifact{}, err
	}
	if !bytes.Equal(data, canonical) {
		return Artifact{}, ErrNonCanonicalEncoding
	}
	return artifact, nil
}

// CanonicalDigest returns the SHA-256 digest of EncodeArtifact output.
func CanonicalDigest(artifact Artifact) (digest.Digest, error) {
	data, err := EncodeArtifact(artifact)
	if err != nil {
		return "", err
	}
	return digest.FromBytes(data), nil
}

func canonicalArtifact(artifact Artifact) Artifact {
	canonical := artifact
	canonical.Metadata = canonicalMetadata(artifact.Metadata)
	canonical.Payloads = append([]PayloadRef{}, artifact.Payloads...)
	sort.Slice(canonical.Payloads, func(i, j int) bool {
		return canonical.Payloads[i].Name < canonical.Payloads[j].Name
	})
	return canonical
}

func validateWireValue(value any) error {
	switch v := value.(type) {
	case nil:
		return fmt.Errorf("%w: null is forbidden", ErrInvalidArtifact)
	case float32, float64:
		return fmt.Errorf("%w: floating-point values are forbidden", ErrInvalidArtifact)
	case string:
		if !utf8.ValidString(v) || !norm.NFC.IsNormalString(v) {
			return fmt.Errorf("%w: wire text must be valid NFC UTF-8", ErrInvalidArtifact)
		}
	case map[any]any:
		for key, item := range v {
			if _, ok := key.(string); !ok {
				return fmt.Errorf("%w: map keys must be text", ErrInvalidArtifact)
			}
			if err := validateWireValue(key); err != nil {
				return err
			}
			if err := validateWireValue(item); err != nil {
				return err
			}
		}
	case []any:
		for _, item := range v {
			if err := validateWireValue(item); err != nil {
				return err
			}
		}
	}
	return nil
}

func canonicalMetadata(m Metadata) Metadata {
	if m.Labels == nil {
		m.Labels = map[string]string{}
	}
	if m.Annotations == nil {
		m.Annotations = map[string]string{}
	}
	return m
}
