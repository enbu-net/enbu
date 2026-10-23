// Package identity manages repository identities. Hardware private keys are
// opaque: their only cryptographic operation is ECDH.
package identity

import (
	"crypto/ecdh"
	"crypto/mlkem"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io/fs"
	"sync"

	"filippo.io/age"
	"filippo.io/age/tag"
	"filippo.io/hpke"
	hpkecrypto "filippo.io/hpke/crypto"
	hpkeecdh "filippo.io/hpke/crypto/ecdh"
)

// ErrUnavailable marks a device that cannot hold a key in any backend: no
// usable hardware (TPM, Secure Enclave) and no reachable OS keyring. Callers
// show the reason and point at `enbu doctor`; it is not an internal error.
var ErrUnavailable = errors.New("identity backend unavailable")

// UnavailableError is an ErrUnavailable that carries the reason to show.
type UnavailableError struct {
	Reason string
	Err    error // the backend's own error, if any
}

func (e *UnavailableError) Error() string        { return ErrUnavailable.Error() + ": " + e.Reason }
func (e *UnavailableError) Is(target error) bool { return target == ErrUnavailable }
func (e *UnavailableError) Unwrap() error        { return e.Err }

// unavailable reports that no backend can hold a key, for reason and, when
// the backend said why, its cause.
func unavailable(reason string, cause error) error {
	if cause != nil {
		reason += ": " + cause.Error()
	}
	return &UnavailableError{Reason: reason, Err: cause}
}

// keyringError reports a keyring that failed to store or load a key as
// unavailable. A missing entry stays fs.ErrNotExist: the key is gone, the
// keyring is not.
func keyringError(op string, err error) error {
	if errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("%s: %w", op, err)
	}
	return unavailable(op, err)
}

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

// taggedIdentity unwraps age tag stanzas with a hardware P-256 key: either
// classical p256tag, or mlkem768p256tag when an ML-KEM-768 key is paired with
// it. In the hybrid case only the P-256 half is hardware-bound; the ML-KEM
// half runs in software because TPMs and the Secure Enclave APIs enbu uses
// cannot run ML-KEM yet.
type taggedIdentity struct {
	mu        sync.Mutex
	key       HardwareKey
	hpke      hpke.PrivateKey
	recipient *tag.Recipient
	stanza    tagStanza
	closed    bool
}

type tagStanza struct {
	typ     string
	label   string
	encSize int
}

var (
	p256Tag = tagStanza{typ: "p256tag", label: "age-encryption.org/p256tag", encSize: 65}
	// The hybrid enc is the ML-KEM-768 ciphertext followed by the P-256 share.
	mlkem768P256Tag = tagStanza{typ: "mlkem768p256tag", label: "age-encryption.org/mlkem768p256tag", encSize: mlkem.CiphertextSize768 + 65}
)

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
	return &taggedIdentity{key: key, hpke: k, recipient: r, stanza: p256Tag}, nil
}

// NewHybridHardwareIdentity pairs a hardware P-256 key with a software
// ML-KEM-768 key, given as its 64-byte seed, into a tagged hybrid identity.
// Decrypting needs both, so the file key stays out of reach of a quantum
// attacker (ML-KEM) and of anyone without the device (P-256).
func NewHybridHardwareIdentity(key HardwareKey, mlkemSeed []byte) (Identity, error) {
	pk := key.PublicKey()
	if pk == nil || pk.Curve() != ecdh.P256() {
		return nil, errors.New("hardware identity requires a P-256 public key")
	}
	dk, err := mlkem.NewDecapsulationKey768(mlkemSeed)
	if err != nil {
		return nil, fmt.Errorf("ML-KEM-768 seed: %w", err)
	}
	r, err := tag.NewHybridRecipient(append(dk.EncapsulationKey().Bytes(), pk.Bytes()...))
	if err != nil {
		return nil, err
	}
	k, err := hpke.NewHybridPrivateKey(hpkecrypto.DecapsulatorFromDecapsulationKey768(dk), key)
	if err != nil {
		return nil, err
	}
	return &taggedIdentity{key: key, hpke: k, recipient: r, stanza: mlkem768P256Tag}, nil
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
		if s.Type != i.stanza.typ {
			continue
		}
		if len(s.Args) != 2 || len(s.Body) != 32 {
			return nil, fmt.Errorf("malformed %s stanza", i.stanza.typ)
		}
		hint, err := base64.RawStdEncoding.Strict().DecodeString(s.Args[0])
		if err != nil || len(hint) != 4 {
			return nil, fmt.Errorf("malformed %s hint", i.stanza.typ)
		}
		enc, err := base64.RawStdEncoding.Strict().DecodeString(s.Args[1])
		if err != nil || len(enc) != i.stanza.encSize {
			return nil, fmt.Errorf("malformed %s encapsulated key", i.stanza.typ)
		}
		expected, err := i.recipient.Tag(enc)
		if err != nil {
			return nil, err
		}
		if subtle.ConstantTimeCompare(hint, expected) != 1 {
			continue
		}
		r, err := hpke.NewRecipient(enc, i.hpke, hpke.HKDFSHA256(), hpke.ChaCha20Poly1305(), []byte(i.stanza.label))
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

type hybridSoftwareIdentity struct{ *age.HybridIdentity }

func (i *hybridSoftwareIdentity) Recipient() Recipient { return i.HybridIdentity.Recipient() }
func (i *hybridSoftwareIdentity) Close() error         { return nil }

// FromHybrid wraps a software ML-KEM-768 + X25519 identity in the common
// lifecycle interface.
func FromHybrid(i *age.HybridIdentity) Identity { return &hybridSoftwareIdentity{i} }
