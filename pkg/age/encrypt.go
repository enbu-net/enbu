package age

import (
	"bytes"
	"fmt"
	"io"
	"strings"

	"filippo.io/age"
	"filippo.io/age/tag"
)

func EncryptForPublicKeys(plaintext []byte, publicKeys []string) ([]byte, error) {
	recipients := make([]age.Recipient, 0, len(publicKeys))
	for _, pk := range publicKeys {
		r, err := ParseRecipient(pk)
		if err != nil {
			return nil, fmt.Errorf("parsing public key %q: %w", pk, err)
		}
		recipients = append(recipients, r)
	}
	return encrypt(plaintext, recipients...)
}

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

// ParseRecipient accepts the standard X25519 and tagged P-256 age encodings.
func ParseRecipient(s string) (age.Recipient, error) {
	if strings.HasPrefix(s, "age1tag1") {
		return tag.ParseRecipient(s)
	}
	return age.ParseX25519Recipient(s)
}
