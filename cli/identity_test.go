package cli

import (
	"bytes"
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

func (*doctorKeyStore) Doctor() identity.Diagnosis {
	return identity.Diagnosis{
		Backend: "tpm", Reason: "no TPM",
		KeyringAvailable:  true,
		CredsReason:       "decryption failed",
		FallbackAvailable: true, Fallback: "keyring",
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
		"OS keyring available: true", "systemd-creds available: false",
		"systemd-creds reason: decryption failed", "Software fallback: keyring",
		"config: skip", "Healthy: true",
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
	if data["keyring_available"] != true || data["creds_available"] != false || data["creds_reason"] != "decryption failed" {
		t.Fatalf("diagnosis = %+v", data)
	}
}
