package identity

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"testing"
)

func TestECDHSealRoundTrip(t *testing.T) {
	k, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	secret := bytes.Repeat([]byte{7}, 64)
	sealed, err := sealToECDH(k.PublicKey(), secret)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(sealed, secret) {
		t.Fatal("sealed data contains the secret")
	}
	key := &softwareHardwareKey{PrivateKey: k}
	out, err := openFromECDH(key, sealed)
	if err != nil || !bytes.Equal(out, secret) {
		t.Fatalf("open: %x %v", out, err)
	}
	if key.calls != 1 {
		t.Fatalf("open ran %d key exchanges, want 1", key.calls)
	}
	again, err := sealToECDH(k.PublicKey(), secret)
	if err != nil || bytes.Equal(again, sealed) {
		t.Fatal("two seals of the same secret are identical")
	}
}

func TestECDHSealRefusesOtherKeyAndTampering(t *testing.T) {
	k, _ := ecdh.P256().GenerateKey(rand.Reader)
	other, _ := ecdh.P256().GenerateKey(rand.Reader)
	sealed, err := sealToECDH(k.PublicKey(), []byte("seed"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := openFromECDH(&softwareHardwareKey{PrivateKey: other}, sealed); err == nil {
		t.Fatal("another key opened the seal")
	}
	for i := range sealed {
		bad := append([]byte(nil), sealed...)
		bad[i] ^= 1
		if _, err := openFromECDH(&softwareHardwareKey{PrivateKey: k}, bad); err == nil {
			t.Fatalf("opened a seal changed at byte %d", i)
		}
	}
	if _, err := openFromECDH(&softwareHardwareKey{PrivateKey: k}, sealed[:65]); err == nil {
		t.Fatal("opened a seal without ciphertext")
	}
	if _, err := sealToECDH(nil, []byte("seed")); err == nil {
		t.Fatal("sealed to a nil key")
	}
	x, _ := ecdh.X25519().GenerateKey(rand.Reader)
	if _, err := sealToECDH(x.PublicKey(), []byte("seed")); err == nil {
		t.Fatal("sealed to an X25519 key")
	}
}
