//go:build darwin

package identity

import (
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"sync"

	"github.com/enbu-net/enbu/pkg/signing"
)

type enclaveSigner struct {
	mu sync.Mutex
	k  *enclaveKey
	pk signing.PublicKey
}

func newEnclaveSigner(k *enclaveKey) (*enclaveSigner, error) {
	pk, err := signing.P256FromUncompressed(k.pk.Bytes())
	if err != nil {
		return nil, err
	}
	return &enclaveSigner{k: k, pk: pk}, nil
}

func (s *enclaveSigner) Public() signing.PublicKey { return s.pk }
func (s *enclaveSigner) Close() error              { return s.k.Close() }

func (s *enclaveSigner) Sign(domain string, body []byte) ([]byte, error) {
	if err := signing.ValidateDomain(domain); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	k := s.k
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.ref == 0 {
		return nil, errors.New("Secure Enclave signing key is closed")
	}
	a := k.api
	msg := a.data(signing.Message(domain, body))
	defer a.release(msg)
	var nativeErr uintptr
	// The Enclave hashes the message with SHA-256 and returns an X9.62 DER signature.
	der := a.keySign(k.ref, a.constant("kSecKeyAlgorithmECDSASignatureMessageX962SHA256"), msg, &nativeErr)
	if der == 0 {
		return nil, a.nativeError(nativeErr, "signature")
	}
	defer a.release(der)
	var sig struct{ R, S *big.Int }
	if rest, err := asn1.Unmarshal(a.bytes(der), &sig); err != nil || len(rest) != 0 || sig.R == nil || sig.S == nil {
		return nil, errors.New("invalid Secure Enclave signature encoding")
	}
	out, err := signing.P256Signature(sig.R, sig.S)
	if err != nil {
		return nil, fmt.Errorf("Secure Enclave signature: %w", err)
	}
	if err := signing.Verify(s.pk, domain, body, out); err != nil {
		return nil, fmt.Errorf("Secure Enclave produced an invalid signature: %w", err)
	}
	return out, nil
}
