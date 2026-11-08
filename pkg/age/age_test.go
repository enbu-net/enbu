package age_test

import (
	"crypto/ecdh"
	"crypto/mlkem"
	"crypto/rand"
	"strings"
	"testing"

	agecrypto "filippo.io/age"
	"filippo.io/age/tag"
	"github.com/enbu-net/enbu/pkg/age"
)

func TestEncryptDecryptForSeveralRecipients(t *testing.T) {
	a, err := age.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	b, err := age.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, err := age.EncryptForPublicKeys([]byte("API_KEY=pq"), []string{a.PublicKey, b.PublicKey, taggedHybridRecipient(t)})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(ciphertext), "-> mlkem768x25519 ") {
		t.Fatal("ciphertext has no hybrid stanza")
	}
	for _, id := range []*agecrypto.HybridIdentity{a.Identity, b.Identity} {
		out, err := age.Decrypt(ciphertext, id)
		if err != nil || string(out) != "API_KEY=pq" {
			t.Fatalf("decrypt: %q %v", out, err)
		}
	}
	other, _ := age.GenerateKeyPair()
	if _, err := age.Decrypt(ciphertext, other.Identity); err == nil {
		t.Fatal("a stranger decrypted the file")
	}
}

func TestEncryptEmptyPlaintext(t *testing.T) {
	kp, _ := age.GenerateKeyPair()
	ciphertext, err := age.EncryptForPublicKeys(nil, []string{kp.PublicKey})
	if err != nil {
		t.Fatal(err)
	}
	if out, err := age.Decrypt(ciphertext, kp.Identity); err != nil || len(out) != 0 {
		t.Fatalf("decrypt empty: %q %v", out, err)
	}
}

func TestParseRecipientRefusesClassicalKeys(t *testing.T) {
	x, _ := agecrypto.GenerateX25519Identity()
	k, _ := ecdh.P256().GenerateKey(rand.Reader)
	p := k.PublicKey().Bytes()
	classicTag, err := tag.NewClassicRecipient(append([]byte{2 | p[64]&1}, p[1:33]...))
	if err != nil {
		t.Fatal(err)
	}
	pq, _ := age.GenerateKeyPair()
	for name, r := range map[string]string{
		"X25519":           x.Recipient().String(),
		"P-256 tag":        classicTag.String(),
		"truncated hybrid": pq.PublicKey[:len(pq.PublicKey)-1],
		"not a recipient":  "invalid-key",
	} {
		if _, err := age.ParseRecipient(r); err == nil {
			t.Errorf("%s: accepted", name)
		}
		if _, err := age.EncryptForPublicKeys([]byte("x"), []string{r}); err == nil {
			t.Errorf("%s: encrypted", name)
		}
	}
}

func TestRecipientKind(t *testing.T) {
	pq, _ := age.GenerateKeyPair()
	if got := age.RecipientKind(pq.PublicKey); got != "ML-KEM-768 + X25519" {
		t.Fatalf("software kind = %q", got)
	}
	if got := age.RecipientKind(taggedHybridRecipient(t)); got != "ML-KEM-768 + P-256 (hardware)" {
		t.Fatalf("hardware kind = %q", got)
	}
}

func taggedHybridRecipient(t testing.TB) string {
	t.Helper()
	k, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	dk, err := mlkem.GenerateKey768()
	if err != nil {
		t.Fatal(err)
	}
	h, err := tag.NewHybridRecipient(append(dk.EncapsulationKey().Bytes(), k.PublicKey().Bytes()...))
	if err != nil {
		t.Fatal(err)
	}
	return h.String()
}
