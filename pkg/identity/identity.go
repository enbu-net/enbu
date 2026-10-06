// Package identity manages repository identities. Hardware private keys are
// opaque: their only cryptographic operation is ECDH.
package identity

import (
	"crypto/ecdh"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"sync"

	"filippo.io/age"
	"filippo.io/age/tag"
	"filippo.io/hpke"
	hpkeecdh "filippo.io/hpke/crypto/ecdh"
)

type Recipient interface {
	age.Recipient
	String() string
}

type Identity interface {
	age.Identity
	Recipient() Recipient
	Close() error
}

type PublicInfo struct {
	Created   bool   `json:"-"`
	Backend   string `json:"backend"`
	Algorithm string `json:"algorithm"`
	Recipient string `json:"recipient"`
	Device    string `json:"device,omitempty"`
	// DeviceID and Fingerprint describe the separate signing key. They are
	// filled in by the app layer, not stored with the encryption identity.
	DeviceID    string `json:"device_id,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty"`
}

// HardwareKey has deliberately no private-key export method.
type HardwareKey interface {
	hpkeecdh.KeyExchanger
	Close() error
}

type taggedIdentity struct {
	mu        sync.Mutex
	key       HardwareKey
	hpke      hpke.PrivateKey
	recipient *tag.Recipient
	closed    bool
}

func NewHardwareIdentity(key HardwareKey) (Identity, error) {
	pk := key.PublicKey()
	if pk == nil || pk.Curve() != ecdh.P256() {
		return nil, errors.New("hardware identity requires a P-256 public key")
	}
	// crypto/ecdh has already validated the SEC1 point. Compress its encoding
	// for the age tag recipient without handling private key material.
	uncompressed := pk.Bytes()
	compressed := make([]byte, 33)
	compressed[0] = 2 | (uncompressed[64] & 1)
	copy(compressed[1:], uncompressed[1:33])
	r, err := tag.NewClassicRecipient(compressed)
	if err != nil {
		return nil, err
	}
	k, err := hpke.NewDHKEMPrivateKey(key)
	if err != nil {
		return nil, err
	}
	return &taggedIdentity{key: key, hpke: k, recipient: r}, nil
}

func (i *taggedIdentity) Recipient() Recipient { return i.recipient }

func (i *taggedIdentity) Close() error {
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.closed {
		return nil
	}
	i.closed = true
	return i.key.Close()
}

func (i *taggedIdentity) Unwrap(stanzas []*age.Stanza) ([]byte, error) {
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.closed {
		return nil, errors.New("identity is closed")
	}
	for _, s := range stanzas {
		if s.Type != "p256tag" {
			continue
		}
		if len(s.Args) != 2 || len(s.Body) != 32 {
			return nil, errors.New("malformed p256tag stanza")
		}
		hint, err := base64.RawStdEncoding.Strict().DecodeString(s.Args[0])
		if err != nil || len(hint) != 4 {
			return nil, errors.New("malformed p256tag hint")
		}
		enc, err := base64.RawStdEncoding.Strict().DecodeString(s.Args[1])
		if err != nil || len(enc) != 65 {
			return nil, errors.New("malformed p256tag encapsulated key")
		}
		expected, err := i.recipient.Tag(enc)
		if err != nil {
			return nil, err
		}
		if subtle.ConstantTimeCompare(hint, expected) != 1 {
			continue
		}
		r, err := hpke.NewRecipient(enc, i.hpke, hpke.HKDFSHA256(), hpke.ChaCha20Poly1305(), []byte("age-encryption.org/p256tag"))
		if err != nil {
			return nil, fmt.Errorf("hardware ECDH: %w", err)
		}
		fileKey, err := r.Open(nil, s.Body)
		if err != nil {
			continue
		} // A four-byte tag can collide.
		return fileKey, nil
	}
	return nil, age.ErrIncorrectIdentity
}

type softwareIdentity struct{ *age.X25519Identity }

func (i *softwareIdentity) Recipient() Recipient { return i.X25519Identity.Recipient() }
func (i *softwareIdentity) Close() error         { return nil }

// FromX25519 wraps a software identity in the common lifecycle interface.
func FromX25519(i *age.X25519Identity) Identity { return &softwareIdentity{i} }
