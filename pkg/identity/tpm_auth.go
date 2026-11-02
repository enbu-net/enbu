package identity

import (
	"bytes"
	"crypto/hkdf"
	"crypto/sha256"
	"errors"
	"sync"
	"time"
)

// UserVerifier gates the TPM keys behind the user: the keys' authValue is
// derived from a secret that only a verified user can obtain from the
// verifier (on Windows, the PRF of a Windows Hello passkey). Without it, any
// process of the same user could have the TPM decrypt and sign.
//
// The caller clears each returned secret after use, so a verifier must return
// a fresh slice on every call.
type UserVerifier interface {
	// Enroll creates a credential, asks the user to verify, and returns the
	// credential's ID and its secret. It returns ErrUserVerificationUnsupported
	// when the platform cannot derive a secret, and the keys are then created
	// without an authValue.
	Enroll() (credential, secret []byte, err error)
	// Secret asks the user to verify and returns the secret of credential.
	Secret(credential []byte) ([]byte, error)
}

// ErrUserVerificationUnsupported means the verifier works but cannot derive a
// secret on this device, for example because Windows Hello has no PRF.
var ErrUserVerificationUnsupported = errors.New("user verification cannot derive a key secret on this device")

// authTTL is how long a verified secret is reused, so the desktop app and
// `enbu rpc` do not ask the user again for every operation.
const authTTL = 5 * time.Minute

// tpmAuth caches the last verified secret of a backend. One operation loads
// the identity, its sealed seed and the signing key, and all of them share one
// credential, so the user verifies once.
type tpmAuth struct {
	mu         sync.Mutex
	credential []byte
	value      []byte // the authValue derived from the secret
	at         time.Time
	now        func() time.Time
}

func (a *tpmAuth) clock() time.Time {
	if a.now != nil {
		return a.now()
	}
	return time.Now()
}

func (a *tpmAuth) cached(credential []byte) []byte {
	if a.value == nil {
		return nil
	}
	if a.clock().Sub(a.at) > authTTL {
		clear(a.value)
		a.credential, a.value = nil, nil
		return nil
	}
	if credential != nil && !bytes.Equal(credential, a.credential) {
		return nil
	}
	return a.value
}

func (a *tpmAuth) store(credential, secret []byte) ([]byte, error) {
	value, err := deriveAuth(secret)
	clear(secret)
	if err != nil {
		return nil, err
	}
	clear(a.value)
	a.credential, a.value, a.at = credential, value, a.clock()
	return value, nil
}

// deriveAuth turns the verifier's secret into a TPM authValue. SHA-256 is the
// nameAlg of every enbu TPM object, so the authValue may be 32 bytes.
func deriveAuth(secret []byte) ([]byte, error) {
	if len(secret) < 32 {
		return nil, errors.New("user verification returned a short secret")
	}
	return hkdf.Key(sha256.New, secret, nil, "enbu tpm auth v1", 32)
}

// enrollAuth returns the credential and authValue new keys are created with.
// Keys created together (the identity, its seed and the signing key) reuse one
// credential while it is cached. Without a verifier, or when the platform
// cannot derive a secret, keys are created without an authValue.
func (b *TPMBackend) enrollAuth() (credential, value []byte, err error) {
	if b.Verifier == nil {
		return nil, nil, nil
	}
	a := &b.auth
	a.mu.Lock()
	defer a.mu.Unlock()
	if v := a.cached(nil); v != nil {
		return a.credential, bytes.Clone(v), nil
	}
	credential, secret, err := b.Verifier.Enroll()
	if errors.Is(err, ErrUserVerificationUnsupported) {
		return nil, nil, nil
	}
	if err != nil {
		return nil, nil, err
	}
	value, err = a.store(credential, secret)
	if err != nil {
		return nil, nil, err
	}
	return credential, bytes.Clone(value), nil
}

// authFor returns the authValue of keys created under credential, asking the
// user to verify unless a fresh secret is cached. Keys without a credential
// have no authValue. Removing the credential from the metadata does not help
// an attacker: the authValue is part of the TPM object.
func (b *TPMBackend) authFor(credential []byte) ([]byte, error) {
	if len(credential) == 0 {
		return nil, nil
	}
	if b.Verifier == nil {
		return nil, errors.New("this TPM key needs user verification, which is not available")
	}
	a := &b.auth
	a.mu.Lock()
	defer a.mu.Unlock()
	if v := a.cached(credential); v != nil {
		return bytes.Clone(v), nil
	}
	secret, err := b.Verifier.Secret(credential)
	if err != nil {
		return nil, err
	}
	value, err := a.store(credential, secret)
	return bytes.Clone(value), err
}

// keyAuth is the authValue of one loaded key. It is resolved on the key's
// first use, not when the key is loaded, so reading a key's public part (for
// `enbu identity` or the member list) never asks the user to verify. It is
// resolved outside the connection lock, so a verification prompt does not
// block other keys.
type keyAuth struct {
	b          *TPMBackend
	credential []byte
	mu         sync.Mutex
	value      []byte
	resolved   bool
	closed     bool
}

func (k *keyAuth) get() ([]byte, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.closed {
		return nil, errors.New("TPM key is closed")
	}
	if !k.resolved {
		v, err := k.b.authFor(k.credential)
		if err != nil {
			return nil, err
		}
		k.value, k.resolved = v, true
	}
	return k.value, nil
}

// close clears the authValue. The caller holds the connection lock, so no
// command is using the value.
func (k *keyAuth) close() {
	k.mu.Lock()
	defer k.mu.Unlock()
	clear(k.value)
	k.value, k.closed = nil, true
}
