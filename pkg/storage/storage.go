// Package storage stores encrypted payloads and public workspace metadata.
// Versions are backend-specific concurrency tokens, never logical artifact IDs.
package storage

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

const MaxPayloadBytes = 10 * 1024 * 1024
const MaxEnvelopeBytes = MaxPayloadBytes*4/3 + 4096

var (
	ErrNotFound = errors.New("storage object not found")
	ErrConflict = errors.New("storage object changed")
)

type Version string

type Object struct {
	MediaType string `json:"media_type"`
	Data      []byte `json:"data"`
}

type Capabilities struct {
	AtomicUpdates bool `json:"atomic_updates"`
}

type Storage interface {
	Get(context.Context, string) (Object, Version, error)
	// An empty expected version means create only. Otherwise replace exactly
	// the version read by Get. OCI can only check before writing; see Capabilities.
	Put(context.Context, string, Object, Version) error
	List(context.Context, string) ([]string, error)
	Capabilities() Capabilities
}

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

func ValidateObject(o Object) error {
	if o.MediaType == "" || len(o.MediaType) > 256 || strings.ContainsAny(o.MediaType, "\r\n") {
		return errors.New("invalid object media type")
	}
	if len(o.Data) > MaxPayloadBytes {
		return fmt.Errorf("payload exceeds %d bytes", MaxPayloadBytes)
	}
	return nil
}

type envelope struct {
	Version int `json:"version"`
	Object
	Checksum string `json:"checksum"`
}

func Encode(o Object) ([]byte, error) {
	if err := ValidateObject(o); err != nil {
		return nil, err
	}
	return json.Marshal(envelope{Version: 1, Object: o, Checksum: fmt.Sprintf("sha256:%x", sha256.Sum256(o.Data))})
}

func Decode(b []byte) (Object, error) {
	if len(b) > MaxEnvelopeBytes {
		return Object{}, errors.New("storage envelope too large")
	}
	var e envelope
	if err := json.Unmarshal(b, &e); err != nil {
		return Object{}, fmt.Errorf("decoding storage envelope: %w", err)
	}
	if e.Version != 1 {
		return Object{}, errors.New("unsupported storage envelope version")
	}
	if err := ValidateObject(e.Object); err != nil {
		return Object{}, err
	}
	if e.Checksum != fmt.Sprintf("sha256:%x", sha256.Sum256(e.Data)) {
		return Object{}, errors.New("storage payload checksum mismatch")
	}
	return e.Object, nil
}
