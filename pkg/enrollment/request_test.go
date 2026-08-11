package enrollment

import (
	"context"
	"errors"
	"testing"

	"github.com/enbu-net/enbu/pkg/artifact"
)

func TestEnrollmentRequestProvesCandidateSigningKeyAndRejectsTamper(t *testing.T) {
	t.Parallel()

	device, err := artifact.GenerateDeviceIdentity()
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := CreateRequest(context.Background(), device, device.DeviceID(), "github:12345", device.RecipientString())
	if err != nil {
		t.Fatal(err)
	}
	claims, err := VerifyRequest(context.Background(), encoded)
	if err != nil {
		t.Fatal(err)
	}
	if claims.DeviceID != device.DeviceID() || claims.Subject != "github:12345" || claims.X25519Recipient != device.RecipientString() {
		t.Fatalf("claims = %#v", claims)
	}
	tampered := append([]byte(nil), encoded...)
	tampered[len(tampered)-1] ^= 1
	if _, err := VerifyRequest(context.Background(), tampered); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("tampered request = %v", err)
	}
}
