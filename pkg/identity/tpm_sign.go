package identity

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/enbu-net/enbu/pkg/signing"
	"github.com/google/go-tpm/tpm2"
)

// signTemplate is a non-restricted ECDSA P-256 signing-only key. It cannot
// decrypt, so it can never serve as the encryption identity.
func signTemplate() tpm2.TPMTPublic {
	return tpm2.TPMTPublic{
		Type: tpm2.TPMAlgECC, NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{FixedTPM: true, FixedParent: true, SensitiveDataOrigin: true,
			UserWithAuth: true, NoDA: true, SignEncrypt: true, Decrypt: false},
		Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgECC, &tpm2.TPMSECCParms{
			Symmetric: tpm2.TPMTSymDefObject{Algorithm: tpm2.TPMAlgNull},
			Scheme:    tpm2.TPMTECCScheme{Scheme: tpm2.TPMAlgECDSA, Details: tpm2.NewTPMUAsymScheme(tpm2.TPMAlgECDSA, &tpm2.TPMSSigSchemeECDSA{HashAlg: tpm2.TPMAlgSHA256})},
			CurveID:   tpm2.TPMECCNistP256, KDF: tpm2.TPMTKDFScheme{Scheme: tpm2.TPMAlgNull},
		}),
		Unique: tpm2.NewTPMUPublicID(tpm2.TPMAlgECC, &tpm2.TPMSECCPoint{}),
	}
}

type tpmSigner struct {
	*loaded
	pk signing.PublicKey
}

func (s *tpmSigner) Public() signing.PublicKey { return s.pk }

func (s *tpmSigner) Sign(domain string, body []byte) ([]byte, error) {
	if err := signing.ValidateDomain(domain); err != nil {
		return nil, err
	}
	s.c.mu.Lock()
	defer s.c.mu.Unlock()
	if s.closed {
		return nil, errors.New("TPM signing key is closed")
	}
	rsp, err := (tpm2.Sign{
		KeyHandle:  tpm2.AuthHandle{Handle: s.handle, Name: s.name, Auth: tpm2.HMAC(tpm2.TPMAlgSHA256, 16)},
		Digest:     tpm2.TPM2BDigest{Buffer: signing.P256Digest(domain, body)},
		Validation: tpm2.TPMTTKHashCheck{Tag: tpm2.TPMSTHashCheck},
	}).Execute(s.c.t)
	if err != nil {
		return nil, fmt.Errorf("TPM sign: %w", err)
	}
	sig, err := rsp.Signature.Signature.ECDSA()
	if err != nil {
		return nil, err
	}
	if len(sig.SignatureR.Buffer) > 32 || len(sig.SignatureS.Buffer) > 32 {
		return nil, errors.New("invalid TPM signature")
	}
	out, err := signing.P256Signature(new(big.Int).SetBytes(sig.SignatureR.Buffer), new(big.Int).SetBytes(sig.SignatureS.Buffer))
	if err != nil {
		return nil, fmt.Errorf("TPM signature: %w", err)
	}
	if err := signing.Verify(s.pk, domain, body, out); err != nil {
		return nil, fmt.Errorf("TPM produced an invalid signature: %w", err)
	}
	return out, nil
}

func (s *tpmSigner) Close() error { return s.close() }
