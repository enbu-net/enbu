package age

import (
	"bytes"
	"strings"
	"testing"

	"pgregory.net/rapid"
)

// CRYPTO-2: a ciphertext opens only for its recipients, only to what was
// encrypted, and any change makes it fail.
func TestEncryptionRoundTripsOnlyForRecipients(t *testing.T) {
	keys := make([]*KeyPair, 4)
	for i := range keys {
		k, err := GenerateKeyPair()
		if err != nil {
			t.Fatal(err)
		}
		keys[i] = k
	}
	rapid.Check(t, func(t *rapid.T) {
		plaintext := rapid.SliceOfN(rapid.Byte(), 0, 512).Draw(t, "plaintext")
		chosen := rapid.SliceOfNDistinct(rapid.IntRange(0, len(keys)-1), 1, len(keys), rapid.ID[int]).Draw(t, "recipients")
		var recipients []string
		in := map[int]bool{}
		for _, i := range chosen {
			recipients = append(recipients, keys[i].PublicKey)
			in[i] = true
		}
		ct, err := EncryptForPublicKeys(plaintext, recipients)
		if err != nil {
			t.Fatal(err)
		}
		for i, k := range keys {
			got, err := Decrypt(ct, k.Identity)
			switch {
			case in[i] && (err != nil || !bytes.Equal(got, plaintext)):
				t.Fatalf("recipient %d cannot read its ciphertext: %v", i, err)
			case !in[i] && err == nil:
				t.Fatalf("key %d, not a recipient, decrypted the ciphertext", i)
			}
		}
		// Any flipped bit is detected (the header MAC or the payload AEAD).
		bit := rapid.IntRange(0, len(ct)*8-1).Draw(t, "bit")
		altered := append([]byte(nil), ct...)
		altered[bit/8] ^= 1 << (bit % 8)
		if got, err := Decrypt(altered, keys[chosen[0]].Identity); err == nil && !bytes.Equal(got, plaintext) {
			t.Fatalf("a ciphertext with bit %d flipped decrypted to different plaintext", bit)
		} else if err == nil {
			t.Fatalf("a ciphertext with bit %d flipped still decrypts", bit)
		}
		if _, err := Decrypt(ct[:len(ct)-1], keys[chosen[0]].Identity); err == nil {
			t.Fatal("a truncated ciphertext decrypts")
		}
	})
}

// Only post-quantum recipients are accepted: a classical X25519 recipient or
// anything else is refused before encrypting.
func TestOnlyPostQuantumRecipientsAreAccepted(t *testing.T) {
	k, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{
		"age1qyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqs3290gq", // classical X25519
		"", "age1pq1", "AGE1PQ1" + strings.TrimPrefix(k.PublicKey, "age1pq1"), k.PublicKey + "x",
	} {
		if _, err := EncryptForPublicKeys([]byte("x"), []string{k.PublicKey, bad}); err == nil {
			t.Errorf("recipient %q was accepted", bad)
		}
	}
}
