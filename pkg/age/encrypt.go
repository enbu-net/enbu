// Package age encrypts for enbu's recipients: hybrid ML-KEM-768 + X25519
// (software) and tagged hybrid ML-KEM-768 + P-256 (hardware). Classical
// recipients are refused, so every file stays post-quantum.
package age

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"

	"filippo.io/age"
	"filippo.io/age/tag"
)

const (
	prefixHybrid    = "age1pq1"
	prefixTagHybrid = "age1tagpq1"
)

// EncryptForPublicKeys encrypts plaintext for every recipient.
func EncryptForPublicKeys(plaintext []byte, publicKeys []string) ([]byte, error) {
	recipients := make([]age.Recipient, 0, len(publicKeys))
	for _, pk := range publicKeys {
		r, err := ParseRecipient(pk)
		if err != nil {
			return nil, fmt.Errorf("parsing public key %q: %w", pk, err)
		}
		recipients = append(recipients, r)
	}
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

func Decrypt(ciphertext []byte, identities ...age.Identity) ([]byte, error) {
	r, err := age.Decrypt(bytes.NewReader(ciphertext), identities...)
	if err != nil {
		return nil, fmt.Errorf("decrypting: %w", err)
	}
	return io.ReadAll(r)
}

// ParseRecipient accepts the hybrid ML-KEM-768 + X25519 and the tagged hybrid
// ML-KEM-768 + P-256 age encodings.
func ParseRecipient(s string) (age.Recipient, error) {
	switch {
	case strings.HasPrefix(s, prefixTagHybrid):
		return tag.ParseRecipient(s)
	case strings.HasPrefix(s, prefixHybrid):
		return age.ParseHybridRecipient(s)
	}
	return nil, errors.New("not a post-quantum age recipient")
}

// RecipientKind names the key type of a recipient for display.
func RecipientKind(s string) string {
	if strings.HasPrefix(s, prefixTagHybrid) {
		return "ML-KEM-768 + P-256 (hardware)"
	}
	return "ML-KEM-768 + X25519"
}

// KeyPair is a software identity, for tests and tools.
type KeyPair struct {
	Identity  *age.HybridIdentity
	PublicKey string
}

func GenerateKeyPair() (*KeyPair, error) {
	identity, err := age.GenerateHybridIdentity()
	if err != nil {
		return nil, err
	}
	return &KeyPair{Identity: identity, PublicKey: identity.Recipient().String()}, nil
}
