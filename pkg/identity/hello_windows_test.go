//go:build windows && !identitytest

package identity

import (
	"errors"
	"os"
	"testing"
)

// TestHelloVerifierEnroll talks to the real Windows Hello. It needs a person
// at the device, so it runs only with ENBU_TEST_NATIVE_IDENTITY=1; with
// ENBU_TEST_HELLO_PRF=1 a passkey without PRF fails instead of skipping.
func TestHelloVerifierEnroll(t *testing.T) {
	if os.Getenv("ENBU_TEST_NATIVE_IDENTITY") != "1" {
		t.Skip("set ENBU_TEST_NATIVE_IDENTITY=1 to run the Windows Hello test")
	}
	v := newHelloVerifier()
	if v == nil {
		t.Skip("no user-verifying platform authenticator")
	}
	credential, secret, err := v.Enroll()
	if errors.Is(err, ErrUserVerificationUnsupported) {
		if os.Getenv("ENBU_TEST_HELLO_PRF") == "1" {
			t.Fatalf("PRF expected on this device: %v", err)
		}
		t.Skipf("PRF not supported on this device: %v", err)
	}
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = deletePasskey(credential) }()
	if len(credential) == 0 || len(secret) < 32 {
		t.Fatalf("Enroll returned a %d-byte credential and a %d-byte secret", len(credential), len(secret))
	}
	again, err := v.Secret(credential)
	if err != nil {
		t.Fatal(err)
	}
	if string(again) != string(secret) {
		t.Fatal("the passkey's PRF changed between enrollment and assertion")
	}
}
