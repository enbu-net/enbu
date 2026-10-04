package cli

import (
	"errors"
	agecrypto "filippo.io/age"
	"github.com/enbu-net/enbu/pkg/identity"
	"io/fs"
)

func (s *staticKeyStore) Load(workspaceID string) (identity.Identity, error) {
	raw, err := s.loadSecret("enbu", workspaceID)
	if err != nil {
		return nil, err
	}
	if len(raw) == 0 {
		return nil, fs.ErrNotExist
	}
	key, err := agecrypto.ParseX25519Identity(string(raw))
	if err != nil {
		return nil, err
	}
	return identity.FromX25519(key), nil
}
func (s *staticKeyStore) Create(workspaceID string) (identity.Identity, identity.PublicInfo, string, error) {
	id, err := s.Load(workspaceID)
	if errors.Is(err, fs.ErrNotExist) {
		key, e := agecrypto.GenerateX25519Identity()
		if e != nil {
			return nil, identity.PublicInfo{}, "", e
		}
		if e = s.storeSecret("enbu", workspaceID, []byte(key.String())); e != nil {
			return nil, identity.PublicInfo{}, "", e
		}
		id = identity.FromX25519(key)
		err = nil
	}
	if err != nil {
		return nil, identity.PublicInfo{}, "", err
	}
	return id, identity.PublicInfo{Backend: "keyring", Algorithm: "X25519", Recipient: id.Recipient().String()}, "", nil
}
func (s *staticKeyStore) Info(workspaceID string) (identity.PublicInfo, error) {
	id, err := s.Load(workspaceID)
	if err != nil {
		return identity.PublicInfo{}, err
	}
	defer func() { _ = id.Close() }()
	return identity.PublicInfo{Backend: "keyring", Algorithm: "X25519", Recipient: id.Recipient().String()}, nil
}
func (s *staticKeyStore) Doctor() identity.Diagnosis {
	return identity.Diagnosis{FallbackAvailable: true}
}
