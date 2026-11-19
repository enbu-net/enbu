package auth

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/enbu-net/enbu/pkg/fsutil"
	"github.com/enbu-net/enbu/pkg/identity"
)

const (
	tokenSealDomain = "enbu GitHub account seal v1"
	storeFile       = "github-accounts.json"
	maxStoreSize    = 16 << 20
)

var errCorruptStore = errors.New("GitHub TPM store is corrupt; run 'enbu auth reset --yes' and sign in again")

type tpmKeys interface {
	ProbeECDH() error
	CreateECDH() ([]byte, identity.TPMObject, identity.HardwareKey, error)
	LoadECDH([]byte, identity.TPMObject) (identity.HardwareKey, error)
}

type tpmStore struct {
	path string
	keys tpmKeys
}

type tokenKeyMetadata struct {
	Version int                `json:"version"`
	Purpose string             `json:"purpose"`
	Parent  []byte             `json:"parent"`
	Key     identity.TPMObject `json:"key"`
}

type tokenEnvelope struct {
	Metadata tokenKeyMetadata `json:"metadata"`
	Sealed   []byte           `json:"sealed"`
}

func (s tpmStore) readEnvelope() (tokenEnvelope, error) {
	var envelope tokenEnvelope
	fi, err := regularFile(s.path)
	if err != nil {
		return envelope, err
	}
	if fi.Size() > maxStoreSize {
		return envelope, errCorruptStore
	}
	f, err := os.Open(s.path)
	if err != nil {
		return envelope, err
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, maxStoreSize+1))
	if err != nil {
		return envelope, err
	}
	if len(data) > maxStoreSize || decodeStrict(data, &envelope) != nil ||
		envelope.Metadata.Version != 1 || envelope.Metadata.Purpose != tokenSealDomain ||
		len(envelope.Metadata.Parent) != 34 {
		return tokenEnvelope{}, errCorruptStore
	}
	canonical, err := json.Marshal(envelope)
	if err != nil || !bytes.Equal(data, canonical) {
		return tokenEnvelope{}, errCorruptStore
	}
	return envelope, nil
}

func (s tpmStore) load() (storedAccounts, error) {
	envelope, err := s.readEnvelope()
	if errors.Is(err, fs.ErrNotExist) {
		exists, err := hasBackendMarker(filepath.Dir(s.path), tpmSelectionFile)
		if err != nil {
			return storedAccounts{}, err
		}
		if exists {
			return storedAccounts{}, errCorruptStore
		}
		return storedAccounts{}, nil
	}
	if err != nil {
		return storedAccounts{}, err
	}
	key, err := s.keys.LoadECDH(envelope.Metadata.Parent, envelope.Metadata.Key)
	if err != nil {
		return storedAccounts{}, classifyTPMLoad(err)
	}
	defer func() { _ = key.Close() }()
	aad, err := json.Marshal(envelope.Metadata)
	if err != nil {
		return storedAccounts{}, err
	}
	aead, err := tokenAEAD(key)
	if err != nil {
		return storedAccounts{}, err
	}
	data, err := aead.Open(nil, nil, envelope.Sealed, aad)
	if err != nil {
		return storedAccounts{}, errCorruptStore
	}
	defer clear(data)
	var stored storedAccounts
	if decodeStrict(data, &stored) != nil || validateAccounts(stored.Accounts) != nil || !stored.validMigration() {
		return storedAccounts{}, errCorruptStore
	}
	return stored, nil
}

func (s tpmStore) save(stored storedAccounts) error { return s.write(stored, false) }

func (s tpmStore) reset() error {
	// A reset starts a new empty store and retires the legacy entry for this
	// store. It can recover from a TPM clear without reading the old key.
	if _, err := regularFile(s.path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return s.write(storedAccounts{Migration: migrationComplete}, true)
}

func (s tpmStore) write(stored storedAccounts, reset bool) error {
	var envelope tokenEnvelope
	var key identity.HardwareKey
	var err error
	if !reset {
		envelope, err = s.readEnvelope()
	}
	if reset || errors.Is(err, fs.ErrNotExist) {
		envelope.Metadata = tokenKeyMetadata{Version: 1, Purpose: tokenSealDomain}
		envelope.Metadata.Parent, envelope.Metadata.Key, key, err = s.keys.CreateECDH()
	} else if err == nil {
		key, err = s.keys.LoadECDH(envelope.Metadata.Parent, envelope.Metadata.Key)
		err = classifyTPMLoad(err)
	}
	if err != nil {
		return err
	}
	defer func() { _ = key.Close() }()
	aad, err := json.Marshal(envelope.Metadata)
	if err != nil {
		return err
	}
	data, err := json.Marshal(stored)
	if err != nil {
		return err
	}
	defer clear(data)
	aead, err := tokenAEAD(key)
	if err != nil {
		return err
	}
	envelope.Sealed = aead.Seal(nil, nil, data, aad)
	encoded, err := json.Marshal(envelope)
	if err != nil {
		return err
	}
	if len(encoded) > maxStoreSize {
		return errors.New("GitHub account data exceeds the TPM store size limit")
	}
	if err := fsutil.WriteFileAtomic(s.path, encoded, 0o600); err != nil {
		return err
	}
	return markBackend(filepath.Dir(s.path), tpmSelectionFile)
}

// Use the TPM key's own public point as the ECDH peer so that the TPM
// private key is needed for writes as well as reads. The resulting AES key
// stays bound to this store and AES-GCM generates a fresh nonce on each write.
func tokenAEAD(key identity.HardwareKey) (cipher.AEAD, error) {
	shared, err := key.ECDH(key.PublicKey())
	if err != nil {
		return nil, err
	}
	defer clear(shared)
	aesKey, err := hkdf.Key(sha256.New, shared, nil, tokenSealDomain, 32)
	if err != nil {
		return nil, err
	}
	defer clear(aesKey)
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCMWithRandomNonce(block)
}

func classifyTPMLoad(err error) error {
	if err == nil || errors.Is(err, identity.ErrTPMParentChanged) || tpmDenied(err) {
		return err
	}
	return fmt.Errorf("%w: %w", errCorruptStore, err)
}

func regularFile(path string) (os.FileInfo, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() || insecurePermissions(fi) {
		return nil, fmt.Errorf("GitHub credential file %s must be a private regular file", filepath.Base(path))
	}
	return fi, nil
}

func decodeStrict(data []byte, dst any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		// A JSON type error or unknown field can reproduce input. Account
		// data may contain tokens, including in malformed fields.
		return errors.New("invalid GitHub credential data")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("trailing GitHub credential data")
	}
	return nil
}
