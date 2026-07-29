package age_test

import (
	"testing"

	"github.com/enbu-net/enbu/pkg/age"
)

func TestKeyGenAndEncryptDecrypt(t *testing.T) {
	kp, err := age.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	plaintext := []byte("DATABASE_URL=postgres://secret")

	ciphertext, err := age.EncryptForPublicKeys(plaintext, []string{kp.PublicKey})
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	decrypted, err := age.Decrypt(ciphertext, kp.Identity)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}

	if string(decrypted) != string(plaintext) {
		t.Fatalf("got %q, want %q", decrypted, plaintext)
	}
}

func TestMultipleRecipients(t *testing.T) {
	kp1, _ := age.GenerateKeyPair()
	kp2, _ := age.GenerateKeyPair()

	plaintext := []byte("shared secret")

	ciphertext, err := age.EncryptForPublicKeys(plaintext, []string{kp1.PublicKey, kp2.PublicKey})
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	dec1, err := age.Decrypt(ciphertext, kp1.Identity)
	if err != nil {
		t.Fatalf("Decrypt with kp1: %v", err)
	}
	if string(dec1) != string(plaintext) {
		t.Fatalf("kp1: got %q, want %q", dec1, plaintext)
	}

	dec2, err := age.Decrypt(ciphertext, kp2.Identity)
	if err != nil {
		t.Fatalf("Decrypt with kp2: %v", err)
	}
	if string(dec2) != string(plaintext) {
		t.Fatalf("kp2: got %q, want %q", dec2, plaintext)
	}
}

func TestEncryptEmptyPlaintext(t *testing.T) {
	kp, _ := age.GenerateKeyPair()

	ciphertext, err := age.EncryptForPublicKeys([]byte(""), []string{kp.PublicKey})
	if err != nil {
		t.Fatalf("Encrypt empty: %v", err)
	}

	decrypted, err := age.Decrypt(ciphertext, kp.Identity)
	if err != nil {
		t.Fatalf("Decrypt empty: %v", err)
	}

	if string(decrypted) != "" {
		t.Fatalf("expected empty, got %q", decrypted)
	}
}

func TestEncryptForInvalidKey(t *testing.T) {
	_, err := age.EncryptForPublicKeys([]byte("data"), []string{"invalid-key"})
	if err == nil {
		t.Fatal("expected error for invalid public key")
	}
}

func TestDecryptWithWrongKey(t *testing.T) {
	kp1, _ := age.GenerateKeyPair()
	kp2, _ := age.GenerateKeyPair()

	ciphertext, _ := age.EncryptForPublicKeys([]byte("secret"), []string{kp1.PublicKey})

	_, err := age.Decrypt(ciphertext, kp2.Identity)
	if err == nil {
		t.Fatal("expected error decrypting with wrong key")
	}
}
