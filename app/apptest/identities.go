// Package apptest provides in-memory doubles shared by tests that need an
// app.IdentityStore.
package apptest

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"io/fs"
	"sync"

	agecrypto "filippo.io/age"
	"github.com/enbu-net/enbu/pkg/identity"
	"github.com/enbu-net/enbu/pkg/signing"
)

// Identities keeps one software device per workspace in memory. The zero
// value is ready to use.
type Identities struct {
	// Age, when set, is the age identity of every workspace, for tests that
	// encrypt to a key they made up front.
	Age *agecrypto.HybridIdentity

	mu      sync.Mutex
	devices map[string]*keys
}

type keys struct {
	age  *agecrypto.HybridIdentity
	sign ed25519.PrivateKey
}

func (s *Identities) get(workspaceID string, create bool) (*keys, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if k, ok := s.devices[workspaceID]; ok {
		return k, false, nil
	}
	if !create {
		return nil, false, fs.ErrNotExist
	}
	k := &keys{age: s.Age}
	if k.age == nil {
		var err error
		if k.age, err = agecrypto.GenerateHybridIdentity(); err != nil {
			return nil, false, err
		}
	}
	var err error
	if _, k.sign, err = ed25519.GenerateKey(rand.Reader); err != nil {
		return nil, false, err
	}
	if s.devices == nil {
		s.devices = map[string]*keys{}
	}
	s.devices[workspaceID] = k
	return k, true, nil
}

func (k *keys) device() *identity.Device {
	return &identity.Device{Identity: identity.FromHybrid(k.age), Signer: signing.NewEd25519Signer(k.sign)}
}

func (k *keys) info(created bool) identity.PublicInfo {
	id := signing.NewEd25519Signer(k.sign).Public().DeviceID()
	return identity.PublicInfo{Created: created, Backend: "keyring", Algorithm: "MLKEM768-X25519",
		Recipient: k.age.Recipient().String(), DeviceID: string(id), Fingerprint: id.Fingerprint()}
}

func (s *Identities) Create(workspaceID string) (*identity.Device, identity.PublicInfo, string, error) {
	k, created, err := s.get(workspaceID, true)
	if err != nil {
		return nil, identity.PublicInfo{}, "", err
	}
	return k.device(), k.info(created), "", nil
}

func (s *Identities) Load(workspaceID string) (*identity.Device, error) {
	k, _, err := s.get(workspaceID, false)
	if err != nil {
		return nil, err
	}
	return k.device(), nil
}

func (s *Identities) Info(workspaceID string) (identity.PublicInfo, error) {
	k, _, err := s.get(workspaceID, false)
	if err != nil {
		return identity.PublicInfo{}, err
	}
	return k.info(false), nil
}

func (s *Identities) Doctor(context.Context) identity.Diagnosis {
	return identity.Diagnosis{FallbackAvailable: true}
}

// Use installs a device's keys for workspaceID; a nil key is generated.
func (s *Identities) Use(workspaceID string, age *agecrypto.HybridIdentity, sign ed25519.PrivateKey) {
	k, _, err := s.get(workspaceID, true)
	if err != nil {
		panic(err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if age != nil {
		k.age = age
	}
	if sign != nil {
		k.sign = sign
	}
}
