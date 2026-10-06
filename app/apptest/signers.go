// Package apptest provides in-memory doubles shared by tests that need an
// app.IdentityStore.
package apptest

import (
	"crypto/ed25519"
	"crypto/rand"
	"io/fs"
	"sync"

	"github.com/enbu-net/enbu/pkg/identity"
	"github.com/enbu-net/enbu/pkg/signing"
)

// Signers keeps one Ed25519 signing key per workspace in memory. Embed it in
// an identity store double; the zero value is ready to use.
type Signers struct {
	mu   sync.Mutex
	keys map[string]ed25519.PrivateKey
}

func (s *Signers) CreateSigner(workspaceID string) (signing.Signer, identity.SignerInfo, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.keys == nil {
		s.keys = map[string]ed25519.PrivateKey{}
	}
	created := false
	if _, ok := s.keys[workspaceID]; !ok {
		_, key, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, identity.SignerInfo{}, "", err
		}
		s.keys[workspaceID], created = key, true
	}
	signer := signing.NewEd25519Signer(s.keys[workspaceID])
	return signer, infoOf(signer, created), "", nil
}

func (s *Signers) LoadSigner(workspaceID string) (signing.Signer, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key, ok := s.keys[workspaceID]
	if !ok {
		return nil, fs.ErrNotExist
	}
	return signing.NewEd25519Signer(key), nil
}

func (s *Signers) SignerInfo(workspaceID string) (identity.SignerInfo, error) {
	signer, err := s.LoadSigner(workspaceID)
	if err != nil {
		return identity.SignerInfo{}, err
	}
	return infoOf(signer, false), nil
}

// Use installs a signer as the workspace's signing key, for tests that need to
// know a device's identity up front.
func (s *Signers) Use(workspaceID string, key ed25519.PrivateKey) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.keys == nil {
		s.keys = map[string]ed25519.PrivateKey{}
	}
	s.keys[workspaceID] = key
}

func infoOf(s signing.Signer, created bool) identity.SignerInfo {
	id := s.Public().DeviceID()
	return identity.SignerInfo{Created: created, Backend: "keyring", Algorithm: "Ed25519", DeviceID: id, Fingerprint: id.Fingerprint()}
}
