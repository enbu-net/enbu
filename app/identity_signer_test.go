package app

import (
	"errors"
	"testing"

	"github.com/enbu-net/enbu/pkg/identity"
	"github.com/enbu-net/enbu/pkg/signing"
)

func TestIdentityInfoReportsTheDeviceFingerprint(t *testing.T) {
	a := &App{Storage: newMemRegistry(), Identities: newMemKeyStore()}
	prepareApp(t, a, "default")
	created, _, err := a.CreateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	if err := signing.DeviceID(created.DeviceID).Validate(); err != nil {
		t.Fatalf("device id %q: %v", created.DeviceID, err)
	}
	if created.Fingerprint != signing.DeviceID(created.DeviceID).Fingerprint() {
		t.Fatalf("fingerprint %q does not belong to device %q", created.Fingerprint, created.DeviceID)
	}
	// The signing key is separate from the encryption identity.
	if created.DeviceID == created.Recipient {
		t.Fatal("device id must not be the recipient")
	}
	shown, err := a.IdentityInfo()
	if err != nil {
		t.Fatal(err)
	}
	if shown.DeviceID != created.DeviceID || shown.Fingerprint != created.Fingerprint || shown.Recipient != created.Recipient {
		t.Fatalf("identity changed between create and show: %+v vs %+v", created, shown)
	}
}

func TestIdentityInfoWithoutSigningKey(t *testing.T) {
	a := &App{Storage: newMemRegistry(), Identities: newMemKeyStore()}
	prepareApp(t, a, "default")
	// Only the encryption identity exists, as in a workspace created before
	// signing keys: showing it must not fail.
	if _, _, _, err := a.Identities.Create(testWorkspaceID); err != nil {
		t.Fatal(err)
	}
	info, err := a.IdentityInfo()
	if err != nil {
		t.Fatal(err)
	}
	if info.Recipient == "" || info.DeviceID != "" || info.Fingerprint != "" {
		t.Fatalf("unexpected info: %+v", info)
	}
}

// failingSigner makes the signing step fail until fixed, after the encryption
// identity has already been stored.
type failingSigner struct {
	*memKeyStore
	fail bool
}

func (f *failingSigner) CreateSigner(ws string) (signing.Signer, identity.SignerInfo, string, error) {
	if f.fail {
		return nil, identity.SignerInfo{}, "", errors.New("keyring unavailable")
	}
	return f.memKeyStore.CreateSigner(ws)
}

func TestCreateIdentityCanBeRetriedAfterTheSigningStepFails(t *testing.T) {
	store := &failingSigner{memKeyStore: newMemKeyStore(), fail: true}
	a := &App{Storage: newMemRegistry(), Identities: store}
	prepareApp(t, a, "default")
	if _, _, err := a.CreateIdentity(); err == nil {
		t.Fatal("a signing failure was reported as success")
	}
	// The encryption identity exists now; a retry must reuse it and finish.
	first, err := store.Info(testWorkspaceID)
	if err != nil {
		t.Fatal(err)
	}
	store.fail = false
	info, _, err := a.CreateIdentity()
	if err != nil {
		t.Fatalf("retry: %v", err)
	}
	if info.Recipient != first.Recipient || info.DeviceID == "" {
		t.Fatalf("retry did not reuse the identity and add a signer: %+v (was %+v)", info, first)
	}
}
