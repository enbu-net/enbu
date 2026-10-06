// Package wsp implements the workspace security protocol: a signed Control
// chain naming the trusted principals, signed States for secret ciphertexts,
// and local checkpoints that detect rollback.
//
// Storage is untrusted. A ref is only a locator; signatures are the authority.
package wsp

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/fxamacker/cbor/v2"
)

var (
	// ErrInvalid marks an object that failed verification: bad signature, wrong
	// author, malformed or non-canonical encoding.
	ErrInvalid = errors.New("invalid workspace object")
	// ErrRollback marks storage returning something older than, or diverging
	// from, what this client has already accepted.
	ErrRollback = errors.New("storage rolled back or forked workspace state")

	encMode = mustEncMode()
	decMode = mustDecMode()
)

func mustEncMode() cbor.EncMode {
	m, err := cbor.CoreDetEncOptions().EncMode()
	if err != nil {
		panic(err)
	}
	return m
}

func mustDecMode() cbor.DecMode {
	m, err := (cbor.DecOptions{
		DupMapKey:         cbor.DupMapKeyEnforcedAPF,
		IndefLength:       cbor.IndefLengthForbidden,
		TagsMd:            cbor.TagsForbidden,
		UTF8:              cbor.UTF8RejectInvalid,
		ExtraReturnErrors: cbor.ExtraDecErrorUnknownField,
		MaxNestedLevels:   8,
		MaxArrayElements:  4096,
		MaxMapPairs:       64,
	}).DecMode()
	if err != nil {
		panic(err)
	}
	return m
}

func invalid(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, args...))
}

// decodeCanonical decodes data into v and requires that re-encoding v yields
// exactly data, so an object has one byte representation and one digest.
func decodeCanonical(data []byte, v any) error {
	if err := decMode.Unmarshal(data, v); err != nil {
		return invalid("decode: %v", err)
	}
	again, err := encMode.Marshal(v)
	if err != nil {
		return invalid("encode: %v", err)
	}
	if !bytes.Equal(data, again) {
		return invalid("non-canonical encoding")
	}
	return nil
}

// Signed is the stored form of a Control or State: the canonical body bytes and
// a signature over them. The signature covers the body only, never a locator.
type Signed struct {
	Body      []byte `cbor:"body"`
	Signature []byte `cbor:"sig"`
}

func (s Signed) Encode() ([]byte, error) { return encMode.Marshal(s) }

func DecodeSigned(data []byte) (Signed, error) {
	var s Signed
	if err := decodeCanonical(data, &s); err != nil {
		return Signed{}, err
	}
	if len(s.Body) == 0 || len(s.Signature) == 0 {
		return Signed{}, invalid("missing body or signature")
	}
	return s, nil
}
