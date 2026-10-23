package age

import (
	"bytes"
	"fmt"
	"io"
	"strings"

	"filippo.io/age"
	"filippo.io/age/tag"
)

// EncryptForPublicKeys encrypts plaintext for every recipient. When every
// recipient is post-quantum, age keeps the file post-quantum: a classical
// recipient cannot be added to it. A mixed set is encrypted as classical,
// because one classical stanza is enough to recover the file key; see
// PostQuantum.
func EncryptForPublicKeys(plaintext []byte, publicKeys []string) ([]byte, error) {
	recipients := make([]age.Recipient, 0, len(publicKeys))
	for _, pk := range publicKeys {
		r, err := ParseRecipient(pk)
		if err != nil {
			return nil, fmt.Errorf("parsing public key %q: %w", pk, err)
		}
		recipients = append(recipients, r)
	}
	if !PostQuantum(publicKeys) {
		for i, r := range recipients {
			// age refuses to mix post-quantum and classical recipients. Hiding
			// the "postquantum" label is age's documented way to allow it.
			recipients[i] = classicalOnly{r}
		}
	}
	return encrypt(plaintext, recipients...)
}

// classicalOnly hides age.RecipientWithLabels so a post-quantum recipient can
// share a file with classical ones during a migration.
type classicalOnly struct{ r age.Recipient }

func (c classicalOnly) Wrap(fileKey []byte) ([]*age.Stanza, error) { return c.r.Wrap(fileKey) }

func Decrypt(ciphertext []byte, identities ...age.Identity) ([]byte, error) {
	r, err := age.Decrypt(bytes.NewReader(ciphertext), identities...)
	if err != nil {
		return nil, fmt.Errorf("decrypting: %w", err)
	}
	return io.ReadAll(r)
}

func encrypt(plaintext []byte, recipients ...age.Recipient) ([]byte, error) {
	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, recipients...)
	if err != nil {
		return nil, fmt.Errorf("creating age writer: %w", err)
	}
	if _, err := w.Write(plaintext); err != nil {
		return nil, fmt.Errorf("writing plaintext: %w", err)
	}
	if err := w.Close(); err != nil {
		return nil, fmt.Errorf("closing age writer: %w", err)
	}
	return buf.Bytes(), nil
}

const (
	prefixTag          = "age1tag1"
	prefixTagHybrid    = "age1tagpq1"
	prefixHybrid       = "age1pq1"
	recipientX25519    = "X25519"
	recipientP256      = "P-256 (hardware)"
	recipientHybrid    = "ML-KEM-768 + X25519"
	recipientTagHybrid = "ML-KEM-768 + P-256 (hardware)"
)

// ParseRecipient accepts the standard X25519, tagged P-256, hybrid
// ML-KEM-768 + X25519 and tagged hybrid ML-KEM-768 + P-256 age encodings.
func ParseRecipient(s string) (age.Recipient, error) {
	switch {
	case strings.HasPrefix(s, prefixTag), strings.HasPrefix(s, prefixTagHybrid):
		return tag.ParseRecipient(s)
	case strings.HasPrefix(s, prefixHybrid):
		return age.ParseHybridRecipient(s)
	}
	return age.ParseX25519Recipient(s)
}

// IsPostQuantum reports whether s is a hybrid recipient whose stanza stays
// confidential against a quantum computer.
func IsPostQuantum(s string) bool {
	return strings.HasPrefix(s, prefixHybrid) || strings.HasPrefix(s, prefixTagHybrid)
}

// PostQuantum reports whether a file encrypted for recipients would be
// post-quantum: every recipient must be, since any classical stanza unwraps
// the same file key.
func PostQuantum(recipients []string) bool {
	if len(recipients) == 0 {
		return false
	}
	for _, r := range recipients {
		if !IsPostQuantum(r) {
			return false
		}
	}
	return true
}

// RecipientKind names the key type of a recipient for display.
func RecipientKind(s string) string {
	switch {
	case strings.HasPrefix(s, prefixTagHybrid):
		return recipientTagHybrid
	case strings.HasPrefix(s, prefixTag):
		return recipientP256
	case strings.HasPrefix(s, prefixHybrid):
		return recipientHybrid
	}
	return recipientX25519
}
