package auth

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/enbu-net/enbu/pkg/apperr"
	"github.com/enbu-net/enbu/pkg/identity"
	"github.com/enbu-net/enbu/pkg/keystore"
	"github.com/enbu-net/enbu/pkg/winbridge"
)

// CredentialDiagnosis describes local storage independently of the usable
// authentication source. A TPM diagnosis never reads the legacy keyring.
type CredentialDiagnosis struct {
	Backend     string `json:"backend,omitempty"`
	State       string `json:"state"`
	TPM         string `json:"tpm,omitempty"`
	Migration   string `json:"migration,omitempty"`
	Environment bool   `json:"environment_token"`
	SignedIn    bool   `json:"saved_sign_in"`
}

// DiagnoseCredentials checks saved credentials without changing state.
func DiagnoseCredentials() CredentialDiagnosis {
	var d CredentialDiagnosis
	if winbridge.InWSL() {
		if err := winbridge.Shared().GitHubAuth("diagnose", struct{}{}, &d); err != nil {
			d.State = "bridge_unavailable"
		}
	} else {
		d = localStores().diagnose()
	}
	d.Environment = TokenFromEnvironment() != nil
	return d
}

func (s credentialStores) diagnose() CredentialDiagnosis {
	store, tpm, err := s.choose(false)
	if err != nil {
		d := CredentialDiagnosis{Backend: "tpm", TPM: tpm, State: tpm}
		switch {
		case apperr.Is(err, apperr.CodeAuthBackendConflict):
			d.State = "configuration_conflict"
		case apperr.Is(err, apperr.CodeInvalidArgument):
			d.State = "invalid_configuration"
		case d.State == "":
			d.State = "unavailable"
		}
		return d
	}
	d := store.diagnose()
	if tpm != "" {
		d.TPM = tpm
	}
	return d
}

func (s keyringStore) diagnose() CredentialDiagnosis {
	d := CredentialDiagnosis{Backend: "keyring", State: "available"}
	stored, err := s.load()
	if err != nil {
		d.State = keyringStatus(err)
	}
	d.SignedIn = len(stored.Accounts) > 0
	return d
}

func (s tpmStore) diagnose() CredentialDiagnosis {
	d := CredentialDiagnosis{Backend: "tpm", TPM: "available", State: "available"}
	stored, err := s.load()
	if err != nil {
		d.State = tpmStatus(err)
		return d
	}
	d.SignedIn = len(stored.Accounts) > 0
	d.Migration = stored.Migration
	if d.Migration == "" {
		d.Migration = "legacy_unchecked"
		if known, _ := hasBackendMarker(filepath.Dir(s.path), keyringSelectionFile); known {
			d.Migration = "required"
		}
	}
	return d
}

func keyringStatus(err error) string {
	switch {
	case errors.Is(err, keystore.ErrLocked):
		return "keyring_locked"
	case errors.Is(err, keystore.ErrNoKeyring), errors.Is(err, fs.ErrNotExist):
		return "keyring_missing"
	default:
		return "unavailable"
	}
}

// MigrateCredentials moves legacy keyring accounts to the TPM store.
func MigrateCredentials() error { return maintainCredentials("migrate") }

// ResetCredentials resets the selected credential store without changing Workspace Identity.
func ResetCredentials() error { return maintainCredentials("reset") }

func maintainCredentials(operation string) error {
	if winbridge.InWSL() {
		return bridgeAuthError(winbridge.Shared().GitHubAuth(operation, struct{}{}, nil))
	}
	return localStores().maintain(operation)
}

func (s credentialStores) maintain(operation string) error {
	return s.withLock(func() error {
		if operation == "reset" && s.mode == "keyring" {
			return s.resetToKeyring()
		}
		store, _, err := s.choose(operation == "migrate")
		if err != nil {
			return err
		}
		if operation == "migrate" {
			return authStoreError(s.migrate(store))
		}
		return authStoreError(store.reset())
	})
}

// resetToKeyring is an explicit destructive recovery for a removed TPM. Clear
// any legacy account before releasing the TPM binding so it cannot resurface.
func (s credentialStores) resetToKeyring() error {
	paths := []string{s.path, filepath.Join(filepath.Dir(s.path), tpmSelectionFile)}
	for _, path := range paths {
		if _, err := regularFile(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
	}
	if err := s.ring.reset(); err != nil {
		return err
	}
	for _, path := range paths {
		if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
	}
	return nil
}

func bridgeAuthError(err error) error {
	if errors.Is(err, identity.ErrUnavailable) {
		return apperr.Wrap(apperr.CodeIdentityUnavailable, "Windows enbu bridge unavailable", err, nil)
	}
	return err
}
