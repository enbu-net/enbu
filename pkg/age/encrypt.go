package age

import (
	"bytes"
	"fmt"
	"io"

	"filippo.io/age"
)

func EncryptForPublicKeys(plaintext []byte, publicKeys []string) ([]byte, error) {
	recipients := make([]*age.X25519Recipient, 0, len(publicKeys))
	for _, pk := range publicKeys {
		r, err := age.ParseX25519Recipient(pk)
		if err != nil {
			return nil, fmt.Errorf("parsing public key %q: %w", pk, err)
		}
		recipients = append(recipients, r)
	}
	return encrypt(plaintext, recipients...)
}

func Decrypt(ciphertext []byte, identities ...*age.X25519Identity) ([]byte, error) {
	ids := make([]age.Identity, len(identities))
	for i, id := range identities {
		ids[i] = id
	}
	r, err := age.Decrypt(bytes.NewReader(ciphertext), ids...)
	if err != nil {
		return nil, fmt.Errorf("decrypting: %w", err)
	}
	return io.ReadAll(r)
}

func encrypt(plaintext []byte, recipients ...*age.X25519Recipient) ([]byte, error) {
	recs := make([]age.Recipient, len(recipients))
	for i, r := range recipients {
		recs[i] = r
	}
	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, recs...)
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
