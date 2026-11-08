package apptest

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io/fs"
	"testing"

	agecrypto "filippo.io/age"
	"github.com/enbu-net/enbu/pkg/signing"
)

func TestIdentitiesCreateOnceThenReuse(t *testing.T) {
	var s Identities
	if _, err := s.Load("ws"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("load before create: %v", err)
	}
	if _, err := s.Info("ws"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("info before create: %v", err)
	}
	first, info, _, err := s.Create("ws")
	if err != nil {
		t.Fatal(err)
	}
	if !info.Created || info.DeviceID != string(first.Signer.Public().DeviceID()) || info.Recipient != first.Identity.Recipient().String() {
		t.Fatalf("first create: %+v", info)
	}
	_, again, _, err := s.Create("ws")
	if err != nil {
		t.Fatal(err)
	}
	if again.Created || again.DeviceID != info.DeviceID || again.Recipient != info.Recipient {
		t.Fatalf("second create must reuse the keys: %+v", again)
	}
	_, other, _, _ := s.Create("other")
	if other.DeviceID == info.DeviceID || other.Recipient == info.Recipient {
		t.Fatal("two workspaces share keys")
	}
}

func TestIdentitiesUseInstallsKnownKeys(t *testing.T) {
	_, sign, _ := ed25519.GenerateKey(rand.Reader)
	age, _ := agecrypto.GenerateHybridIdentity()
	var s Identities
	s.Use("ws", age, sign)
	d, err := s.Load("ws")
	if err != nil {
		t.Fatal(err)
	}
	if d.Signer.Public().DeviceID() != signing.NewEd25519Signer(sign).Public().DeviceID() || d.Identity.Recipient().String() != age.Recipient().String() {
		t.Fatal("Use did not install the given keys")
	}
	shared := Identities{Age: age}
	d, _, _, _ = shared.Create("any")
	if d.Identity.Recipient().String() != age.Recipient().String() {
		t.Fatal("Age is not used for new workspaces")
	}
}
