package age_test

import (
	"crypto/ecdh"
	"crypto/mlkem"
	"crypto/rand"
	"fmt"
	"strings"
	"testing"

	agecrypto "filippo.io/age"
	"filippo.io/age/tag"
	"github.com/enbu-net/enbu/pkg/age"
)

func TestHybridRecipientRoundTrip(t *testing.T) {
	a, err := age.GenerateHybridKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	b, err := age.GenerateHybridKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(a.PublicKey, "age1pq1") {
		t.Fatalf("unexpected recipient %q", a.PublicKey)
	}
	ciphertext, err := age.EncryptForPublicKeys([]byte("API_KEY=pq"), []string{a.PublicKey, b.PublicKey})
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
		t.Fatal("classical identity decrypted a post-quantum file")
	}
}

func TestMixedRecipientsEncryptAsClassical(t *testing.T) {
	pq, _ := age.GenerateHybridKeyPair()
	classic, _ := age.GenerateKeyPair()
	recipients := []string{pq.PublicKey, classic.PublicKey}
	if age.PostQuantum(recipients) {
		t.Fatal("a mixed set must not be reported as post-quantum")
	}
	ciphertext, err := age.EncryptForPublicKeys([]byte("mixed"), recipients)
	if err != nil {
		t.Fatalf("mixed set must still encrypt during a migration: %v", err)
	}
	for _, id := range []agecrypto.Identity{pq.Identity, classic.Identity} {
		out, err := age.Decrypt(ciphertext, id)
		if err != nil || string(out) != "mixed" {
			t.Fatalf("decrypt: %q %v", out, err)
		}
	}
}

func TestPostQuantum(t *testing.T) {
	pq, _ := age.GenerateHybridKeyPair()
	classic, _ := age.GenerateKeyPair()
	tagged := taggedHybridRecipient(t)
	for _, tc := range []struct {
		recipients []string
		want       bool
	}{
		{nil, false},
		{[]string{classic.PublicKey}, false},
		{[]string{pq.PublicKey}, true},
		{[]string{pq.PublicKey, tagged}, true},
		{[]string{pq.PublicKey, classic.PublicKey}, false},
	} {
		if got := age.PostQuantum(tc.recipients); got != tc.want {
			t.Errorf("PostQuantum(%d recipients) = %v, want %v", len(tc.recipients), got, tc.want)
		}
	}
}

func TestParseRecipientAndKind(t *testing.T) {
	pq, _ := age.GenerateHybridKeyPair()
	classic, _ := age.GenerateKeyPair()
	k, _ := ecdh.P256().GenerateKey(rand.Reader)
	p := k.PublicKey().Bytes()
	compressed := append([]byte{2 | p[64]&1}, p[1:33]...)
	classicTag, err := tag.NewClassicRecipient(compressed)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ recipient, kind string }{
		{classic.PublicKey, "X25519"},
		{classicTag.String(), "P-256 (hardware)"},
		{pq.PublicKey, "ML-KEM-768 + X25519"},
		{taggedHybridRecipient(t), "ML-KEM-768 + P-256 (hardware)"},
	} {
		if _, err := age.ParseRecipient(tc.recipient); err != nil {
			t.Errorf("ParseRecipient(%.16s...): %v", tc.recipient, err)
		}
		if got := age.RecipientKind(tc.recipient); got != tc.kind {
			t.Errorf("RecipientKind(%.16s...) = %q, want %q", tc.recipient, got, tc.kind)
		}
	}
	// A corrupted hybrid key must not fall through to the X25519 parser.
	if _, err := age.ParseRecipient(pq.PublicKey[:len(pq.PublicKey)-1]); err == nil {
		t.Fatal("accepted a truncated hybrid recipient")
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

// recipientSet builds n recipients of one kind for the benchmarks.
func recipientSet(b *testing.B, kind string, n int) ([]string, agecrypto.Identity) {
	b.Helper()
	out := make([]string, n)
	var first agecrypto.Identity
	for i := range out {
		switch kind {
		case "x25519":
			kp, err := age.GenerateKeyPair()
			if err != nil {
				b.Fatal(err)
			}
			out[i] = kp.PublicKey
			if i == 0 {
				first = kp.Identity
			}
		case "mlkem768x25519":
			kp, err := age.GenerateHybridKeyPair()
			if err != nil {
				b.Fatal(err)
			}
			out[i] = kp.PublicKey
			if i == 0 {
				first = kp.Identity
			}
		}
	}
	return out, first
}

// BenchmarkEncrypt compares writing one environment for a team. The
// header-bytes metric is the ciphertext size minus the plaintext, which is
// almost entirely the per-recipient stanzas.
func BenchmarkEncrypt(b *testing.B) {
	plaintext := []byte(strings.Repeat("KEY=0123456789abcdef0123456789abcdef\n", 50))
	for _, kind := range []string{"x25519", "mlkem768x25519"} {
		for _, n := range []int{1, 10, 50} {
			b.Run(fmt.Sprintf("%s/recipients=%d", kind, n), func(b *testing.B) {
				recipients, _ := recipientSet(b, kind, n)
				var size int
				for b.Loop() {
					ct, err := age.EncryptForPublicKeys(plaintext, recipients)
					if err != nil {
						b.Fatal(err)
					}
					size = len(ct)
				}
				b.ReportMetric(float64(size-len(plaintext)), "header-bytes")
				b.ReportMetric(float64(len(recipients[0])), "recipient-chars")
			})
		}
	}
}

// BenchmarkDecrypt measures one member opening a file written for ten
// members, with their stanza listed last.
func BenchmarkDecrypt(b *testing.B) {
	plaintext := []byte(strings.Repeat("KEY=0123456789abcdef0123456789abcdef\n", 50))
	for _, kind := range []string{"x25519", "mlkem768x25519"} {
		b.Run(kind, func(b *testing.B) {
			recipients, id := recipientSet(b, kind, 10)
			recipients[0], recipients[9] = recipients[9], recipients[0]
			ct, err := age.EncryptForPublicKeys(plaintext, recipients)
			if err != nil {
				b.Fatal(err)
			}
			for b.Loop() {
				if _, err := age.Decrypt(ct, id); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
