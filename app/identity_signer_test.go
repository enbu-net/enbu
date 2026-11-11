package app

import (
	"testing"

	"github.com/enbu-net/enbu/app/apptest"
	"github.com/enbu-net/enbu/pkg/signing"
)

func TestIdentityInfoReportsTheDeviceFingerprint(t *testing.T) {
	a := &App{Storage: newMemRegistry(), Identities: &apptest.Identities{}}
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
