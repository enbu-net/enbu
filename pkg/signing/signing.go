// Package signing defines the signing keys, canonical signatures and device
// identifiers used by the workspace security protocol. Signing keys are never
// used for encryption.
package signing

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strings"
)

type Algorithm string

const (
	P256    Algorithm = "p256"
	Ed25519 Algorithm = "ed25519"
)

const (
	DomainControl = "enbu.workspace-control.v1"
	DomainState   = "enbu.workspace-state.v1"
	DomainJoin    = "enbu.join-request.v1"

	deviceIDDomain = "enbu.device-id.v1\x00"
	p256SigSize    = 64
)

var (
	ErrInvalidKey       = errors.New("invalid signing public key")
	ErrInvalidSignature = errors.New("invalid signature")
	ErrInvalidDomain    = errors.New("invalid signing domain")
)

// PublicKey is canonical: P-256 uses the 33-byte SEC1 compressed point and
// Ed25519 the 32-byte raw key.
type PublicKey struct {
	Alg   Algorithm `cbor:"alg" json:"alg"`
	Bytes []byte    `cbor:"key" json:"key"`
}

// DeviceID is derived from the public key, so an ID names exactly one key.
type DeviceID string

// Signer has deliberately no private-key export method.
type Signer interface {
	Public() PublicKey
	// Sign signs domain || 0x00 || body and returns the canonical signature.
	Sign(domain string, body []byte) ([]byte, error)
	Close() error
}

func (k PublicKey) Validate() error {
	switch k.Alg {
	case P256:
		if _, err := parseP256(k.Bytes); err != nil {
			return err
		}
	case Ed25519:
		if len(k.Bytes) != ed25519.PublicKeySize {
			return fmt.Errorf("%w: ed25519 key must be %d bytes", ErrInvalidKey, ed25519.PublicKeySize)
		}
	default:
		return fmt.Errorf("%w: unsupported algorithm %q", ErrInvalidKey, k.Alg)
	}
	return nil
}

func parseP256(b []byte) (*ecdsa.PublicKey, error) {
	if len(b) != 33 {
		return nil, fmt.Errorf("%w: p256 key must be compressed (33 bytes)", ErrInvalidKey)
	}
	x, y := elliptic.UnmarshalCompressed(elliptic.P256(), b)
	if x == nil {
		return nil, fmt.Errorf("%w: point is not on P-256", ErrInvalidKey)
	}
	uncompressed := make([]byte, 65)
	uncompressed[0] = 4
	x.FillBytes(uncompressed[1:33])
	y.FillBytes(uncompressed[33:])
	key, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), uncompressed)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidKey, err)
	}
	return key, nil
}

// P256FromUncompressed converts a SEC1 uncompressed point to the canonical key.
func P256FromUncompressed(b []byte) (PublicKey, error) {
	if _, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), b); err != nil {
		return PublicKey{}, fmt.Errorf("%w: %w", ErrInvalidKey, err)
	}
	compressed := make([]byte, 33)
	compressed[0] = 2 | (b[64] & 1)
	copy(compressed[1:], b[1:33])
	return PublicKey{Alg: P256, Bytes: compressed}, nil
}

func (k PublicKey) DeviceID() DeviceID {
	h := sha256.New()
	h.Write([]byte(deviceIDDomain))
	h.Write([]byte(k.Alg))
	h.Write([]byte{0})
	h.Write(k.Bytes)
	return DeviceID(hex.EncodeToString(h.Sum(nil)))
}

func (id DeviceID) Validate() error {
	b, err := hex.DecodeString(string(id))
	if err != nil || len(b) != sha256.Size || string(id) != strings.ToLower(string(id)) {
		return fmt.Errorf("invalid device id %q", string(id))
	}
	return nil
}

// Fingerprint is the short form people compare out of band: the first 20 hex
// characters in groups of four.
func (id DeviceID) Fingerprint() string {
	s := string(id)
	if len(s) < 20 {
		return s
	}
	var parts []string
	for i := 0; i < 20; i += 4 {
		parts = append(parts, s[i:i+4])
	}
	return strings.Join(parts, "-")
}

// ValidateDomain rejects a domain that contains the separator byte. Without
// this, ("a\x00b", "c") and ("a", "b\x00c") would produce the same message.
func ValidateDomain(domain string) error {
	if domain == "" || strings.IndexByte(domain, 0) >= 0 {
		return ErrInvalidDomain
	}
	return nil
}

// Message is the exact byte string that is signed: domain || 0x00 || body.
func Message(domain string, body []byte) []byte {
	m := make([]byte, 0, len(domain)+1+len(body))
	m = append(m, domain...)
	m = append(m, 0)
	return append(m, body...)
}

// Verify checks sig over domain || 0x00 || body. P-256 signatures must be
// fixed-size r||s with low-S.
func Verify(pk PublicKey, domain string, body, sig []byte) error {
	if err := pk.Validate(); err != nil {
		return err
	}
	if err := ValidateDomain(domain); err != nil {
		return err
	}
	msg := Message(domain, body)
	switch pk.Alg {
	case Ed25519:
		if len(sig) != ed25519.SignatureSize || !ed25519.Verify(pk.Bytes, msg, sig) {
			return ErrInvalidSignature
		}
	case P256:
		if len(sig) != p256SigSize {
			return ErrInvalidSignature
		}
		r, s := new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])
		if s.Cmp(halfOrder()) > 0 {
			return fmt.Errorf("%w: high-S", ErrInvalidSignature)
		}
		key, _ := parseP256(pk.Bytes)
		digest := sha256.Sum256(msg)
		if !ecdsa.Verify(key, digest[:], r, s) {
			return ErrInvalidSignature
		}
	}
	return nil
}

func halfOrder() *big.Int {
	return new(big.Int).Rsh(elliptic.P256().Params().N, 1)
}

// P256Signature builds the canonical r||s form, folding s into the low half.
// Hardware backends that return (r, s) or DER use this. Values that cannot be
// part of a valid ECDSA signature are rejected rather than encoded.
func P256Signature(r, s *big.Int) ([]byte, error) {
	n := elliptic.P256().Params().N
	if r == nil || s == nil || r.Sign() <= 0 || s.Sign() <= 0 || r.Cmp(n) >= 0 || s.Cmp(n) >= 0 {
		return nil, fmt.Errorf("%w: r and s must be in [1, N-1]", ErrInvalidSignature)
	}
	if s.Cmp(halfOrder()) > 0 {
		s = new(big.Int).Sub(n, s)
	}
	out := make([]byte, p256SigSize)
	r.FillBytes(out[:32])
	s.FillBytes(out[32:])
	return out, nil
}

// P256Digest is the hash a hardware backend must sign for domain and body.
func P256Digest(domain string, body []byte) []byte {
	d := sha256.Sum256(Message(domain, body))
	return d[:]
}

type ed25519Signer struct{ key ed25519.PrivateKey }

// NewEd25519Signer wraps a software key in the Signer interface.
func NewEd25519Signer(key ed25519.PrivateKey) Signer { return &ed25519Signer{key} }

// Public returns the zero PublicKey, which fails Validate, for a malformed key.
func (s *ed25519Signer) Public() PublicKey {
	if len(s.key) != ed25519.PrivateKeySize {
		return PublicKey{}
	}
	return PublicKey{Alg: Ed25519, Bytes: append([]byte(nil), s.key.Public().(ed25519.PublicKey)...)}
}
func (s *ed25519Signer) Sign(domain string, body []byte) ([]byte, error) {
	if err := ValidateDomain(domain); err != nil {
		return nil, err
	}
	if len(s.key) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("%w: ed25519 private key must be %d bytes", ErrInvalidKey, ed25519.PrivateKeySize)
	}
	return ed25519.Sign(s.key, Message(domain, body)), nil
}
func (s *ed25519Signer) Close() error { return nil }

type p256Signer struct{ key *ecdsa.PrivateKey }

// NewP256Signer wraps a software P-256 key. Hardware backends implement Signer
// directly; this exists for tests and for platforms without one. A key whose
// public point does not belong to its private scalar is rejected, since its
// signatures could never verify under Public().
func NewP256Signer(key *ecdsa.PrivateKey) (Signer, error) {
	if key == nil || key.Curve != elliptic.P256() {
		return nil, fmt.Errorf("%w: signer requires a P-256 private key", ErrInvalidKey)
	}
	d, err := key.ECDH() // validates the private scalar
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidKey, err)
	}
	pub, err := key.PublicKey.Bytes()
	if err != nil || !bytes.Equal(pub, d.PublicKey().Bytes()) {
		return nil, fmt.Errorf("%w: public key does not match the private key", ErrInvalidKey)
	}
	return &p256Signer{key}, nil
}

func (s *p256Signer) Public() PublicKey {
	raw, _ := s.key.PublicKey.Bytes() // cannot fail for a key on P-256
	pk, _ := P256FromUncompressed(raw)
	return pk
}
func (s *p256Signer) Sign(domain string, body []byte) ([]byte, error) {
	if err := ValidateDomain(domain); err != nil {
		return nil, err
	}
	r, ss, err := ecdsa.Sign(rand.Reader, s.key, P256Digest(domain, body))
	if err != nil {
		return nil, err
	}
	return P256Signature(r, ss)
}
func (s *p256Signer) Close() error { return nil }
