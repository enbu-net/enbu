//go:build (linux || windows) && !identitytest

package auth

import (
	"os"
	"testing"

	"github.com/enbu-net/enbu/pkg/apperr"
)

func TestTPMNativeCredentialLifecycle(t *testing.T) {
	if os.Getenv("ENBU_TEST_NATIVE_AUTH") != "1" {
		t.Skip("set ENBU_TEST_NATIVE_AUTH=1 on a TPM 2.0 device")
	}
	stubBackend(t)
	t.Setenv("ENBU_AUTH_BACKEND", "hardware")
	want := testAccount(1)
	if d := DiagnoseCredentials(); d.Backend != "tpm" || d.State != "available" {
		t.Fatalf("native TPM unavailable: %+v", d)
	}
	if err := SaveToken(want); err != nil {
		t.Fatal(err)
	}
	if got, err := LoadToken(); err != nil || *got != *want {
		t.Fatalf("could not reload the native TPM account: %v", err)
	}
	if err := DeleteAccount(""); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadToken(); !apperr.Is(err, apperr.CodeNotAuthenticated) {
		t.Fatalf("load after deletion = %v", err)
	}
}
