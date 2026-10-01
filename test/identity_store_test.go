//go:build scenario

package test

import (
	"errors"
	agecrypto "filippo.io/age"
	"github.com/enbu-net/enbu/pkg/identity"
	"io/fs"
	"strings"
)

func (s *mockKeyStore) Load(owner, repo string) (identity.Identity, error) {
	raw, err := s.loadSecret("enbu", strings.ToLower(owner+"/"+repo))
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
func (s *mockKeyStore) Create(owner, repo string) (identity.Identity, identity.PublicInfo, string, error) {
	id, err := s.Load(owner, repo)
	if errors.Is(err, fs.ErrNotExist) {
		key, e := agecrypto.GenerateX25519Identity()
		if e != nil {
			return nil, identity.PublicInfo{}, "", e
		}
		if e = s.storeSecret("enbu", strings.ToLower(owner+"/"+repo), []byte(key.String())); e != nil {
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
func (s *mockKeyStore) Info(owner, repo string) (identity.PublicInfo, error) {
	id, err := s.Load(owner, repo)
	if err != nil {
		return identity.PublicInfo{}, err
	}
	defer func() { _ = id.Close() }()
	return identity.PublicInfo{Backend: "keyring", Algorithm: "X25519", Recipient: id.Recipient().String()}, nil
}
func (s *mockKeyStore) Doctor() identity.Diagnosis {
	return identity.Diagnosis{FallbackAvailable: true}
}
