package identity

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// noKeyringVault is a keyring whose probe fails, as on a server without a
// Secret Service.
type noKeyringVault struct{ memoryVault }

func (noKeyringVault) Probe() error { return errNoReply }

// Without a keyring, software keys go to systemd-creds, and load from there
// even once a keyring appears.
func TestSoftwareKeysFallBackToSystemdCreds(t *testing.T) {
	creds := memoryVault{}
	m := &Manager{Dir: t.TempDir(), Vault: noKeyringVault{memoryVault{}}, Creds: creds}
	id, info, warning, err := m.Create("ws")
	if err != nil {
		t.Fatal(err)
	}
	_ = id.Close()
	if info.Backend != backendCreds {
		t.Fatalf("backend = %q, want %q", info.Backend, backendCreds)
	}
	if !strings.Contains(warning, "using systemd-creds") {
		t.Fatalf("warning = %q", warning)
	}
	s, signer, _, err := m.CreateSigner("ws")
	if err != nil {
		t.Fatal(err)
	}
	_ = s.Close()
	if signer.Backend != backendCreds {
		t.Fatalf("signer backend = %q, want %q", signer.Backend, backendCreds)
	}
	if len(creds) != 2 {
		t.Fatalf("systemd-creds holds %d keys, want 2", len(creds))
	}

	m.Vault = memoryVault{}
	if _, err := m.Load("ws"); err != nil {
		t.Fatalf("Load with a keyring present: %v", err)
	}
	if _, err := m.LoadSigner("ws"); err != nil {
		t.Fatalf("LoadSigner with a keyring present: %v", err)
	}
	m.Mode = "hardware"
	if _, err := m.Load("ws"); err == nil {
		t.Fatal("a systemd-creds key satisfied the hardware mode")
	}
}

func TestKeyringIsPreferredOverSystemdCreds(t *testing.T) {
	creds := memoryVault{}
	m := &Manager{Dir: t.TempDir(), Vault: memoryVault{}, Creds: creds}
	_, info, _, err := m.Create("ws")
	if err != nil {
		t.Fatal(err)
	}
	if info.Backend != backendKeyring || len(creds) != 0 {
		t.Fatalf("backend = %q with %d systemd-creds keys", info.Backend, len(creds))
	}
}

func TestNoSoftwareBackendIsUnavailable(t *testing.T) {
	m := &Manager{Dir: t.TempDir(), Vault: noKeyringVault{memoryVault{}}, Creds: noKeyringVault{memoryVault{}}}
	if _, _, _, err := m.Create("ws"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("Create = %v, want unavailable", err)
	}
	if _, _, _, err := m.CreateSigner("ws"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("CreateSigner = %v, want unavailable", err)
	}
}

func TestDoctorReportsTheSoftwareFallback(t *testing.T) {
	for _, tt := range []struct {
		name      string
		m         *Manager
		available bool
		fallback  string
	}{
		{"keyring", &Manager{Vault: memoryVault{}, Creds: memoryVault{}}, true, backendKeyring},
		{"systemd-creds", &Manager{Vault: noKeyringVault{}, Creds: memoryVault{}}, true, backendCreds},
		{"neither", &Manager{Vault: noKeyringVault{}, Creds: noKeyringVault{}}, false, ""},
		{"no systemd-creds", &Manager{Vault: noKeyringVault{}}, false, ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			d := tt.m.Doctor(context.Background())
			if d.FallbackAvailable != tt.available || d.Fallback != tt.fallback {
				t.Fatalf("Doctor = %+v", d)
			}
			if !tt.available && d.FallbackReason == "" {
				t.Fatal("no reason given")
			}
		})
	}
}

func TestDoctorChecksCredsEvenWithKeyring(t *testing.T) {
	for _, available := range []bool{true, false} {
		m := &Manager{Vault: memoryVault{}, Creds: memoryVault{}}
		if !available {
			m.Creds = noKeyringVault{}
		}
		d := m.Doctor(context.Background())
		if !d.KeyringAvailable || d.CredsAvailable != available || d.Fallback != backendKeyring {
			t.Fatalf("Doctor = %+v", d)
		}
		if !available && d.CredsReason == "" {
			t.Fatal("missing creds failure reason")
		}
	}
}

type contextProbeVault struct {
	memoryVault
	got context.Context
}

func (v *contextProbeVault) Probe(ctx context.Context) error { v.got = ctx; return nil }
func TestDoctorPassesContextToCredentials(t *testing.T) {
	creds := &contextProbeVault{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m := &Manager{Vault: memoryVault{}, Creds: creds}
	d := m.Doctor(ctx)
	if !d.CredsAvailable || creds.got != ctx {
		t.Fatal("credentials probe lost the caller context")
	}
	cancel()
	d = m.Doctor(ctx)
	if d.CredsAvailable || d.KeyringAvailable {
		t.Fatal("cancelled diagnosis probed an available backend")
	}
}
