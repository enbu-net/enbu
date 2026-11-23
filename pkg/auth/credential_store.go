package auth

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"slices"

	"github.com/enbu-net/enbu/pkg/apperr"
	"github.com/enbu-net/enbu/pkg/config"
	"github.com/enbu-net/enbu/pkg/fsutil"
	"github.com/enbu-net/enbu/pkg/identity"
	"github.com/enbu-net/enbu/pkg/keystore"
	"github.com/google/go-tpm/tpm2"
)

const (
	tokenKeyringService  = "enbu"
	tokenKeyringAccount  = "github-oauth"
	tpmSelectionFile     = "tpm-selected"
	keyringSelectionFile = "keyring-selected"
	migrationPending     = "cleanup_pending"
	migrationComplete    = "complete"
)

var (
	tokenBackend = keystore.New()
	authStoreDir = func() string { return filepath.Join(config.DefaultDataDir(), "github-auth") }
	systemTPM    = func() tpmKeys {
		if tpm := identity.SystemTPM(); tpm != nil {
			return tpm
		}
		return nil
	}
)

type credentialStore interface {
	load() (storedAccounts, error)
	save(storedAccounts) error
	reset() error
	diagnose() CredentialDiagnosis
}

type keyringStore struct {
	backend keystore.Backend
	dir     string
}

func (s keyringStore) read() ([]byte, error) {
	data, err := s.backend.Load(tokenKeyringService, tokenKeyringAccount)
	return bytes.Clone(data), err
}

func (s keyringStore) load() (storedAccounts, error) {
	data, err := s.read()
	if errors.Is(err, fs.ErrNotExist) {
		return storedAccounts{}, nil
	}
	if err != nil {
		return storedAccounts{}, keyringError("loading token", err)
	}
	accounts, err := parseAccounts(data)
	clear(data)
	return storedAccounts{Accounts: accounts}, err
}

func (s keyringStore) save(stored storedAccounts) error {
	if len(stored.Accounts) == 0 {
		return s.reset()
	}
	data, err := json.Marshal(stored)
	if err != nil {
		return err
	}
	defer clear(data)
	if err := s.backend.Store(tokenKeyringService, tokenKeyringAccount, data); err != nil {
		return keyringError("saving token", err)
	}
	saved, err := s.read()
	if err != nil {
		return keyringError("verifying saved token", err)
	}
	defer clear(saved)
	if !bytes.Equal(saved, data) {
		return errors.New("verifying saved GitHub token failed")
	}
	return markBackend(s.dir, keyringSelectionFile)
}

func (s keyringStore) reset() error {
	if err := s.deleteEntry(); err != nil {
		return err
	}
	err := os.Remove(filepath.Join(s.dir, keyringSelectionFile))
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	return err
}

func (s keyringStore) deleteEntry() error {
	if err := s.backend.Delete(tokenKeyringService, tokenKeyringAccount); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return keyringError("removing token", err)
	}
	return nil
}

func keyringError(op string, err error) error {
	switch {
	case errors.Is(err, keystore.ErrLocked):
		return apperr.Wrap(apperr.CodeKeyringLocked, op+": "+err.Error(), err, nil)
	case errors.Is(err, keystore.ErrNoKeyring):
		return apperr.Wrap(apperr.CodeUnavailable, op+": "+err.Error(), err, nil)
	}
	return fmt.Errorf("%s: %w", op, err)
}

type credentialStores struct {
	mode string
	path string
	tpm  tpmKeys
	ring keyringStore
}

func localStores() credentialStores {
	mode := os.Getenv("ENBU_AUTH_BACKEND")
	if mode == "" {
		mode = "auto"
	}
	dir := authStoreDir()
	return credentialStores{
		mode: mode, path: filepath.Join(dir, storeFile),
		tpm: systemTPM(), ring: keyringStore{backend: tokenBackend, dir: dir},
	}
}

func (s credentialStores) hasTPMStore() (bool, error) {
	if _, err := privateDirectory(filepath.Dir(s.path)); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return false, nil
		}
		return false, err
	}
	// Even an invalid file occupies the backend slot. It must not cause a
	// fallback to the old keyring.
	if _, err := os.Lstat(s.path); !errors.Is(err, fs.ErrNotExist) {
		return err == nil, err
	}
	return hasBackendMarker(filepath.Dir(s.path), tpmSelectionFile)
}

func hasBackendMarker(dir, name string) (bool, error) {
	_, err := regularFile(filepath.Join(dir, name))
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	return err == nil, err
}

func markBackend(dir, name string) error {
	if exists, err := hasBackendMarker(dir, name); err != nil || exists {
		return err
	}
	return fsutil.WriteFileAtomic(filepath.Join(dir, name), nil, 0o600)
}

func privateDirectory(path string) (os.FileInfo, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !fi.IsDir() || insecurePermissions(fi) {
		return nil, errors.New("GitHub credential directory must be a private directory")
	}
	return fi, nil
}

func insecurePermissions(fi os.FileInfo) bool {
	// Windows uses the per-user LocalAppData ACL inherited by new files.
	return runtime.GOOS != "windows" && fi.Mode().Perm()&0o077 != 0
}

func (s credentialStores) lock() (*os.File, error) {
	dir := filepath.Dir(s.path)
	if err := fsutil.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	if _, err := privateDirectory(dir); err != nil {
		return nil, err
	}
	lock := filepath.Join(dir, "accounts.lock")
	if _, err := regularFile(lock); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	return fsutil.LockFile(lock, true)
}

func (s credentialStores) choose(forceHardware bool) (credentialStore, string, error) {
	switch s.mode {
	case "auto", "hardware", "keyring":
	default:
		return nil, "", apperr.New(apperr.CodeInvalidArgument, "ENBU_AUTH_BACKEND must be auto, hardware, or keyring", nil)
	}
	exists, err := s.hasTPMStore()
	if err != nil {
		return nil, "", err
	}
	if s.mode == "keyring" {
		if exists || forceHardware {
			return nil, "", apperr.New(apperr.CodeAuthBackendConflict, "ENBU_AUTH_BACKEND=keyring conflicts with the GitHub TPM store or migration; use auto or hardware", nil)
		}
		return s.ring, "", nil
	}
	if s.mode == "hardware" && !exists && !forceHardware {
		keyring, err := hasBackendMarker(filepath.Dir(s.path), keyringSelectionFile)
		if err != nil {
			return nil, "", err
		}
		if keyring {
			return nil, "", apperr.New(apperr.CodeAuthBackendConflict, "saved GitHub credentials use the OS keyring; run 'enbu auth migrate' to move them to the TPM", nil)
		}
	}
	if s.tpm == nil {
		err = identity.ErrTPMUnsupported
	} else {
		err = tpmAccessError(s.tpm.ProbeECDH())
	}
	if err == nil {
		return tpmStore{path: s.path, keys: s.tpm}, "", nil
	}
	state := tpmStatus(err)
	if !exists && !forceHardware && s.mode == "auto" && (state == "tpm_absent" || state == "tpm_unsupported") {
		return s.ring, state, nil
	}
	if exists && (state == "tpm_absent" || state == "tpm_unsupported") {
		return nil, state, apperr.Wrap(apperr.CodeAuthTPMRecovery, "saved GitHub credentials require the original TPM", err, nil)
	}
	if apperr.Is(err, apperr.CodeAuthTPMAccessDenied) {
		return nil, state, err
	}
	return nil, state, apperr.Wrap(apperr.CodeUnavailable, "GitHub TPM store unavailable: "+err.Error(), err, nil)
}

func tpmAccessError(err error) error {
	if errors.Is(err, fs.ErrPermission) || errors.Is(err, tpm2.TPMRCAuthFail) || errors.Is(err, tpm2.TPMRCBadAuth) {
		return apperr.Wrap(apperr.CodeAuthTPMAccessDenied, "cannot access the TPM for GitHub credentials", err, nil)
	}
	return err
}

func tpmStatus(err error) string {
	switch {
	case apperr.Is(err, apperr.CodeAuthTPMAccessDenied):
		return "tpm_permission_denied"
	case errors.Is(err, fs.ErrNotExist):
		return "tpm_absent"
	case errors.Is(err, identity.ErrTPMUnsupported):
		return "tpm_unsupported"
	case errors.Is(err, identity.ErrTPMParentChanged):
		return "tpm_changed"
	case errors.Is(err, errCorruptStore):
		return "corrupt"
	default:
		return "unavailable"
	}
}

func (s credentialStores) migrate(store credentialStore) error {
	current, err := store.load()
	if err != nil || current.Migration == migrationComplete {
		return err
	}
	legacy, err := s.ring.read()
	if errors.Is(err, fs.ErrNotExist) {
		current.Migration, current.LegacyDigest = migrationComplete, ""
		return store.save(current)
	}
	if err != nil {
		return keyringError("reading the legacy GitHub entry", err)
	}
	defer clear(legacy)
	sum := sha256.Sum256(legacy)
	digest := hex.EncodeToString(sum[:])
	if current.Migration != migrationPending {
		accounts, err := parseAccounts(legacy)
		if err != nil {
			return err
		}
		seen := make(map[int64]bool, len(current.Accounts))
		for _, token := range current.Accounts {
			seen[token.UserID] = true
		}
		merged := accounts[:0]
		for _, token := range accounts {
			if !seen[token.UserID] {
				merged = append(merged, token)
			}
		}
		current.Accounts = append(merged, current.Accounts...)
		current.Migration, current.LegacyDigest = migrationPending, digest
		if err := store.save(current); err != nil {
			return err
		}
		verified, err := store.load()
		if err != nil {
			return err
		}
		if verified.Migration != current.Migration || verified.LegacyDigest != current.LegacyDigest ||
			!slices.Equal(verified.Accounts, current.Accounts) {
			return errors.New("verifying GitHub credential migration failed")
		}
	} else if digest != current.LegacyDigest {
		return errors.New("the legacy GitHub entry changed after migration; its credentials were kept")
	}
	if err := s.ring.deleteEntry(); err != nil {
		return err
	}
	current.Migration, current.LegacyDigest = migrationComplete, ""
	return store.save(current)
}

func (s storedAccounts) validMigration() bool {
	switch s.Migration {
	case migrationPending:
		digest, err := hex.DecodeString(s.LegacyDigest)
		return err == nil && len(digest) == sha256.Size
	case "", migrationComplete:
		return s.LegacyDigest == ""
	default:
		return false
	}
}

func authStoreError(err error) error {
	switch {
	case errors.Is(err, identity.ErrTPMParentChanged):
		return apperr.Wrap(apperr.CodeAuthTPMRecovery, "the GitHub store belongs to the previous TPM; run 'enbu auth reset --yes' and sign in again", err, nil)
	case errors.Is(err, errCorruptStore):
		return apperr.Wrap(apperr.CodeAuthTPMRecovery, errCorruptStore.Error(), err, nil)
	}
	return err
}
