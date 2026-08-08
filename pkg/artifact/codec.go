package artifact

import (
	"bytes"
	"errors"
	"fmt"
	"reflect"
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
		MaxArrayElements:  MaxEdges,
		MaxMapPairs:       MaxEdges,
	}).DecMode()
	if err != nil {
		panic(fmt.Sprintf("create strict CBOR decoder: %v", err))
	}
	return mode
}

// MarshalCanonical encodes v using RFC 8949 Core Deterministic Encoding.
// Artifact revisions should normally use EncodeRevision, which additionally
// validates the contract and canonicalizes set-like slices.
func MarshalCanonical(v any) ([]byte, error) {
	if err := validateWireValue(reflect.ValueOf(v), 0); err != nil {
		return nil, err
	}
	return canonicalEncMode.Marshal(v)
}

// UnmarshalStrict rejects duplicate map keys, indefinite-length values, tags,
// invalid UTF-8, unknown struct fields, excessive nesting, and trailing data.
func UnmarshalStrict(data []byte, destination any) error {
	if destination == nil {
		return errors.New("artifact: nil decode destination")
	}
	if err := strictDecMode.Unmarshal(data, destination); err != nil {
		return fmt.Errorf("decode artifact CBOR: %w", err)
	}
	if err := validateWireValue(reflect.ValueOf(destination), 0); err != nil {
		return err
	}
	return nil
}

// EncodeRevision returns the sole canonical wire representation of revision.
// Payloads are ordered by name and edges by ID without mutating the caller.
func EncodeRevision(revision Revision) ([]byte, error) {
	if err := revision.Validate(); err != nil {
		return nil, err
	}
	canonical := canonicalRevision(revision)
	data, err := MarshalCanonical(canonical)
	if err != nil {
		return nil, fmt.Errorf("encode revision: %w", err)
	}
	if len(data) > MaxRevisionBytes {
		return nil, fmt.Errorf("%w: revision exceeds %d encoded bytes", ErrInvalidArtifact, MaxRevisionBytes)
	}
	return data, nil
}

// DecodeRevision accepts only the exact canonical representation emitted by
// EncodeRevision. This prevents alternate encodings from acquiring the same
// semantic meaning while carrying a different content digest.
func DecodeRevision(data []byte) (Revision, error) {
	var revision Revision
	if err := UnmarshalStrict(data, &revision); err != nil {
		return Revision{}, err
	}
	canonical, err := EncodeRevision(revision)
	if err != nil {
		return Revision{}, err
	}
	if !bytes.Equal(data, canonical) {
		return Revision{}, ErrNonCanonicalEncoding
	}
	return revision, nil
}

// CanonicalDigest returns the SHA-256 digest of EncodeRevision output.
func CanonicalDigest(revision Revision) (digest.Digest, error) {
	data, err := EncodeRevision(revision)
	if err != nil {
		return "", err
	}
	return digest.FromBytes(data), nil
}

func canonicalRevision(revision Revision) Revision {
	canonical := revision
	canonical.Payloads = append([]PayloadRef(nil), revision.Payloads...)
	sort.Slice(canonical.Payloads, func(i, j int) bool {
		return canonical.Payloads[i].Name < canonical.Payloads[j].Name
	})
	canonical.Edges = append([]Edge(nil), revision.Edges...)
	sort.Slice(canonical.Edges, func(i, j int) bool {
		return canonical.Edges[i].ID < canonical.Edges[j].ID
	})
	return canonical
}

func validateWireValue(value reflect.Value, depth int) error {
	if !value.IsValid() {
		return nil
	}
	if depth > 64 {
		return fmt.Errorf("%w: wire value exceeds validation depth", ErrInvalidArtifact)
	}
	for value.Kind() == reflect.Interface || value.Kind() == reflect.Pointer {
		if value.IsNil() {
			return nil
		}
		value = value.Elem()
		depth++
		if depth > 64 {
			return fmt.Errorf("%w: wire value exceeds validation depth", ErrInvalidArtifact)
		}
	}

	switch value.Kind() {
	case reflect.Float32, reflect.Float64:
		return fmt.Errorf("%w: floating-point values are not allowed", ErrInvalidArtifact)
	case reflect.String:
		text := value.String()
		if !utf8.ValidString(text) || !norm.NFC.IsNormalString(text) {
			return fmt.Errorf("%w: wire text must be valid NFC UTF-8", ErrInvalidArtifact)
		}
	case reflect.Map:
		iterator := value.MapRange()
		for iterator.Next() {
			key := iterator.Key()
			for key.Kind() == reflect.Interface {
				key = key.Elem()
			}
			if key.Kind() != reflect.String {
				return fmt.Errorf("%w: CBOR map keys must be text strings", ErrInvalidArtifact)
			}
			if err := validateWireValue(key, depth+1); err != nil {
				return err
			}
			if err := validateWireValue(iterator.Value(), depth+1); err != nil {
				return err
			}
		}
	case reflect.Struct:
		typeOfValue := value.Type()
		for i := range value.NumField() {
			if typeOfValue.Field(i).PkgPath != "" {
				continue
			}
			if err := validateWireValue(value.Field(i), depth+1); err != nil {
				return err
			}
		}
	case reflect.Array, reflect.Slice:
		if value.Type().Elem().Kind() == reflect.Uint8 {
			return nil
		}
		for i := range value.Len() {
			if err := validateWireValue(value.Index(i), depth+1); err != nil {
				return err
			}
		}
	}
	return nil
}
