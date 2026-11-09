package identity

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"testing"

	"github.com/enbu-net/enbu/pkg/keystore"
	"github.com/enbu-net/enbu/pkg/signing"
	"github.com/google/go-tpm/tpm2/transport"
)

type forbiddenTPM struct{ fakeHardware }

func (*forbiddenTPM) CreateSigner() (signing.Signer, *SignerMetadata, error) {
	return nil, nil, errors.New("a denied TPM cannot create keys")
}
func (*forbiddenTPM) LoadSigner(*SignerMetadata) (signing.Signer, error) {
	return nil, errors.New("a denied TPM cannot load keys")
}

func (*forbiddenTPM) Probe() Diagnosis {
	return Diagnosis{Backend: "tpm", Denied: true, Reason: "permission denied; add your user to the tss group"}
}

// probedVault is a keyring whose probe fails with err.
type probedVault struct {
	memoryVault
	err error
}

func (v probedVault) Probe(context.Context) error { return v.err }

// A TPM this user may not open is not replaced by a software key: neither
// the identity nor the signing key falls back, unless the person asks for the
// keyring explicitly.
func TestDeniedHardwareDoesNotFallBack(t *testing.T) {
	vault := memoryVault{}
	m := &Manager{Dir: t.TempDir(), Vault: vault, Hardware: &forbiddenTPM{}}
	if _, _, _, err := m.Create("ws"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("Create with a denied TPM = %v, want unavailable", err)
	}
	if _, _, _, err := m.CreateSigner("ws"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("CreateSigner with a denied TPM = %v, want unavailable", err)
	}
	if len(vault) != 0 {
		t.Fatalf("a software key was stored: %v", vault)
	}
	d := m.Doctor(context.Background())
	if !d.Denied || !d.FallbackAvailable || d.FallbackReason == "" {
		t.Fatalf("Doctor = %+v", d)
	}

	m.Mode = "keyring"
	if _, info, _, err := m.Create("ws"); err != nil || info.Backend != backendKeyring {
		t.Fatalf("Create with ENBU_IDENTITY_BACKEND=keyring = %+v, %v", info, err)
	}
}

// A locked keyring is reported as locked, not as missing, and keeps
// keystore.ErrLocked in the chain for the app to give it its own code.
func TestLockedKeyringIsReportedAsLocked(t *testing.T) {
	locked := fmt.Errorf("%w: unlock it", keystore.ErrLocked)
	m := &Manager{Dir: t.TempDir(), Vault: probedVault{memoryVault{}, locked}, Hardware: &fakeHardware{}}
	_, _, _, err := m.Create("ws")
	if !errors.Is(err, ErrUnavailable) || !errors.Is(err, keystore.ErrLocked) {
		t.Fatalf("Create with a locked keyring = %v", err)
	}
	d := m.Doctor(context.Background())
	if !d.KeyringLocked || d.KeyringAvailable || d.FallbackAvailable {
		t.Fatalf("Doctor = %+v", d)
	}

	missing := fmt.Errorf("%w: no Secret Service", keystore.ErrNoKeyring)
	m.Vault = probedVault{memoryVault{}, missing}
	if _, _, _, err := m.Create("ws"); !errors.Is(err, ErrUnavailable) || errors.Is(err, keystore.ErrLocked) {
		t.Fatalf("Create without a keyring = %v", err)
	}
	if d := m.Doctor(context.Background()); d.KeyringLocked {
		t.Fatalf("Doctor without a keyring = %+v", d)
	}
}

// The TPM probe tells a TPM the user may not open from a missing one.
func TestTPMProbeSeparatesDeniedFromMissing(t *testing.T) {
	for name, tc := range map[string]struct {
		err    error
		denied bool
	}{
		"denied":  {fmt.Errorf("open /dev/tpmrm0: %w", fs.ErrPermission), true},
		"missing": {fmt.Errorf("open /dev/tpmrm0: %w", fs.ErrNotExist), false},
	} {
		t.Run(name, func(t *testing.T) {
			b := &TPMBackend{Device: "/dev/tpmrm0", Open: func() (transport.TPMCloser, error) { return nil, tc.err }}
			if d := b.Probe(); d.Available || d.Denied != tc.denied {
				t.Fatalf("Probe = %+v", d)
			}
		})
	}
}
