// Package secretmap implements the SecretMap semantic schema independently of dotenv.
package secretmap

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"unicode/utf8"

	"github.com/enbu-net/enbu/pkg/artifact"
	"github.com/enbu-net/enbu/pkg/content"
	"github.com/fxamacker/cbor/v2"
	"github.com/opencontainers/go-digest"
)

const (
	MediaType       = "application/vnd.enbu.secret-map+cbor"
	PayloadName     = "content"
	MaxPayloadBytes = 16 * 1024 * 1024
	MaxEntries      = 4096
	MaxKeyBytes     = 1024
)

var (
	ErrInvalidSecretMap     = errors.New("invalid SecretMap")
	ErrNonCanonicalEncoding = errors.New("non-canonical SecretMap encoding")
	ErrUnsupportedSchema    = errors.New("unsupported SecretMap schema")
	encMode                 = mustEncodingMode()
	decMode                 = mustDecodingMode()
)

// SecretMap maps semantic names to secret text. Names are not constrained to
// environment-variable syntax; that constraint belongs to the dotenv exporter.
// Values are preserved exactly, including Unicode normalization and whitespace.
type SecretMap map[string]string

func Schema() artifact.TypeRef {
	return artifact.TypeRef{Group: "schemas.enbu.net", Version: "v1", Kind: "SecretMap"}
}

func mustEncodingMode() cbor.EncMode {
	mode, err := cbor.CoreDetEncOptions().EncMode()
	if err != nil {
		panic(err)
	}
	return mode
}

func mustDecodingMode() cbor.DecMode {
	mode, err := (cbor.DecOptions{
		DupMapKey:        cbor.DupMapKeyEnforcedAPF,
		IndefLength:      cbor.IndefLengthForbidden,
		TagsMd:           cbor.TagsForbidden,
		UTF8:             cbor.UTF8RejectInvalid,
		MaxNestedLevels:  4,
		MaxArrayElements: 16,
		MaxMapPairs:      MaxEntries,
	}).DecMode()
	if err != nil {
		panic(err)
	}
	return mode
}

func (s SecretMap) Validate() error {
	if len(s) > MaxEntries {
		return fmt.Errorf("%w: too many entries", ErrInvalidSecretMap)
	}
	// Bound allocation before encoding. The exact encoded-size check follows.
	total := 0
	for key, value := range s {
		if len(key) == 0 || len(key) > MaxKeyBytes || !utf8.ValidString(key) || !utf8.ValidString(value) {
			return fmt.Errorf("%w: invalid text", ErrInvalidSecretMap)
		}
		if len(key) > MaxPayloadBytes-total {
			return fmt.Errorf("%w: payload too large", ErrInvalidSecretMap)
		}
		total += len(key)
		if len(value) > MaxPayloadBytes-total {
			return fmt.Errorf("%w: payload too large", ErrInvalidSecretMap)
		}
		total += len(value)
	}
	return nil
}

// Encode emits one canonical CBOR text-to-text map, including {} for nil.
// Unlike Artifact metadata, secret payload text must never be normalized.
func Encode(secrets SecretMap) ([]byte, error) {
	if err := secrets.Validate(); err != nil {
		return nil, err
	}
	if secrets == nil {
		secrets = SecretMap{}
	}
	data, err := encMode.Marshal(secrets)
	if err != nil {
		return nil, fmt.Errorf("encode SecretMap: %w", err)
	}
	if len(data) > MaxPayloadBytes {
		return nil, fmt.Errorf("%w: payload too large", ErrInvalidSecretMap)
	}
	return data, nil
}

func Decode(data []byte) (SecretMap, error) {
	if len(data) > MaxPayloadBytes {
		return nil, fmt.Errorf("%w: payload too large", ErrInvalidSecretMap)
	}
	var secrets SecretMap
	if err := decMode.Unmarshal(data, &secrets); err != nil {
		return nil, fmt.Errorf("%w: decode: %w", ErrInvalidSecretMap, err)
	}
	canonical, err := Encode(secrets)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(data, canonical) {
		return nil, ErrNonCanonicalEncoding
	}
	return secrets, nil
}

// NewArtifact returns metadata and detached payload bytes, without publishing
// either to storage or interpreting any metadata as a destination.
func NewArtifact(uid artifact.UUID, metadata artifact.Metadata, secrets SecretMap) (artifact.Artifact, []byte, error) {
	data, err := Encode(secrets)
	if err != nil {
		return artifact.Artifact{}, nil, err
	}
	a := artifact.Artifact{
		APIVersion: artifact.APIVersion, UID: uid, Schema: Schema(), Metadata: metadata,
		Payloads: []artifact.PayloadRef{{Name: PayloadName, MediaType: MediaType, Digest: digest.FromBytes(data), Size: uint64(len(data))}},
	}
	if err := a.Validate(); err != nil {
		return artifact.Artifact{}, nil, err
	}
	return a, data, nil
}

// ReadArtifact checks schema-specific constraints and verifies content before
// decoding it. Only this bounded semantic handler materializes a secret map.
func ReadArtifact(ctx context.Context, a artifact.Artifact, source content.BlobSource) (SecretMap, error) {
	if err := a.Validate(); err != nil {
		return nil, err
	}
	if a.Schema != Schema() {
		return nil, ErrUnsupportedSchema
	}
	if len(a.Payloads) != 1 || a.Payloads[0].Name != PayloadName || a.Payloads[0].MediaType != MediaType {
		return nil, fmt.Errorf("%w: expected one SecretMap content payload", ErrInvalidSecretMap)
	}
	ref := a.Payloads[0]
	if ref.Size > MaxPayloadBytes {
		return nil, fmt.Errorf("%w: payload too large", ErrInvalidSecretMap)
	}
	var buffer bytes.Buffer
	if err := content.Copy(ctx, &buffer, source, ref); err != nil {
		return nil, err
	}
	return Decode(buffer.Bytes())
}
