package apptest

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io/fs"
	"testing"

	"github.com/enbu-net/enbu/pkg/signing"
)

func TestSignersCreateOnceThenReuse(t *testing.T) {
	var s Signers
	if _, err := s.LoadSigner("ws"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("load before create: %v", err)
	}
	if _, err := s.SignerInfo("ws"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("info before create: %v", err)
	}
	first, info, _, err := s.CreateSigner("ws")
	if err != nil {
		t.Fatal(err)
	}
	if !info.Created || info.DeviceID != first.Public().DeviceID() || info.Fingerprint != info.DeviceID.Fingerprint() {
		t.Fatalf("first create: %+v", info)
	}
	second, again, _, err := s.CreateSigner("ws")
	if err != nil {
		t.Fatal(err)
	}
	if again.Created || again.DeviceID != info.DeviceID || second.Public().DeviceID() != info.DeviceID {
		t.Fatalf("second create must reuse the key: %+v", again)
	}
	other, otherInfo, _, _ := s.CreateSigner("other")
	if otherInfo.DeviceID == info.DeviceID || other.Public().DeviceID() == info.DeviceID {
		t.Fatal("two workspaces share a signing key")
	}
}

func TestSignersUseInstallsAKnownKey(t *testing.T) {
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	var s Signers
	s.Use("ws", key)
	loaded, err := s.LoadSigner("ws")
	if err != nil {
		t.Fatal(err)
	}
	want := signing.NewEd25519Signer(key).Public().DeviceID()
	if loaded.Public().DeviceID() != want {
		t.Fatal("Use did not install the given key")
	}
}
