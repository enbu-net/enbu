package cli

import (
	"bytes"
	"context"
	"github.com/enbu-net/enbu/pkg/identity"
	"strings"
	"testing"

	"github.com/enbu-net/enbu/app"
)

func TestIdentityCommandsWithoutAuthentication(t *testing.T) {
	store := &staticKeyStore{}
	a := &app.App{Identities: store, RepoDetector: &deleteTestRepoDetector{}}
	prepareCLIApp(t, a)
	created := executeJSON(t, NewWithApp("test", a), "identity", "create", "--json")
	shown := executeJSON(t, NewWithApp("test", a), "identity", "show", "--json")
	if objectField(t, created, "data")["recipient"] != objectField(t, shown, "data")["recipient"] {
		t.Fatal("identity show changed recipient")
	}
	if objectField(t, shown, "data")["backend"] != "keyring" {
		t.Fatal("backend omitted")
	}
	// Doctor needs neither token provider nor repository detector.
	doctor := executeJSON(t, NewWithApp("test", &app.App{Identities: store}), "doctor", "--json")
	if objectField(t, doctor, "data")["fallback_available"] != true {
		t.Fatal("fallback result omitted")
	}
}

type doctorKeyStore struct{ staticKeyStore }

func (*doctorKeyStore) Doctor(context.Context) identity.Diagnosis {
	return identity.Diagnosis{
		Backend: "tpm", Reason: "no TPM",
		KeyringAvailable:  true,
		FallbackAvailable: true,
	}
}

type lockedDoctorKeyStore struct{ staticKeyStore }

func (*lockedDoctorKeyStore) Doctor(context.Context) identity.Diagnosis {
	return identity.Diagnosis{
		Backend: "tpm", Reason: "permission denied", Denied: true,
		KeyringReason: "OS keyring is locked", KeyringLocked: true,
		FallbackReason: "the hardware exists but this user may not use it",
	}
}

// A denied TPM and a locked keyring are each said in plain words, in the
// text output and in the JSON, so the person knows what to fix.
func TestDoctorReportsDeniedHardwareAndLockedKeyring(t *testing.T) {
	a := &app.App{Identities: &lockedDoctorKeyStore{}, RepositoryDir: t.TempDir()}
	cmd := NewWithApp("test", a)
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"doctor"})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"Hardware access denied: true", "OS keyring locked: true", "Software fallback available: false",
		"identity_backend: warn", "this user may not use it", "(identity_unavailable)",
	} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("missing %q in %q", want, out.String())
		}
	}
	data := objectField(t, executeJSON(t, NewWithApp("test", a), "doctor", "--json"), "data")
	if data["denied"] != true || data["keyring_locked"] != true || data["fallback_available"] != false {
		t.Fatalf("diagnosis = %+v", data)
	}
}

func TestDoctorReportsEachBackend(t *testing.T) {
	a := &app.App{Identities: &doctorKeyStore{}, RepositoryDir: t.TempDir()}
	cmd := NewWithApp("test", a)
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"doctor"})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"Hardware: tpm", "Available: false", "Reason: no TPM",
		"OS keyring available: true", "Software fallback available: true",
		"identity_backend: ok", "config: skip", "Healthy: true",
	} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("missing %q in %q", want, out.String())
		}
	}
	result := executeJSON(t, NewWithApp("test", a), "doctor", "--json")
	data := objectField(t, result, "data")
	if data["healthy"] != true || len(data["checks"].([]any)) == 0 {
		t.Fatalf("missing workspace diagnosis: %+v", data)
	}
	if _, ok := data["creds_available"]; ok || data["keyring_available"] != true {
		t.Fatalf("diagnosis = %+v", data)
	}
}
