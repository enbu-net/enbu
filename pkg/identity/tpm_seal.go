package identity

import (
	"bytes"
	"crypto/mlkem"
	"errors"
	"fmt"

	"github.com/google/go-tpm/tpm2"
)

// sealTemplate is the sealed data object that keeps the ML-KEM-768 seed of a
// hybrid identity. TPMs cannot run ML-KEM yet, so the seed is used on the host,
// but at rest it only exists inside this TPM's storage hierarchy: the blob is
// encrypted under the storage primary and cannot be duplicated.
func sealTemplate() tpm2.TPMTPublic {
	return tpm2.TPMTPublic{
		Type: tpm2.TPMAlgKeyedHash, NameAlg: tpm2.TPMAlgSHA256,
		// The caller supplies the data, so SensitiveDataOrigin must be clear.
		ObjectAttributes: tpm2.TPMAObject{FixedTPM: true, FixedParent: true, UserWithAuth: true, NoDA: true},
		Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgKeyedHash,
			&tpm2.TPMSKeyedHashParms{Scheme: tpm2.TPMTKeyedHashScheme{Scheme: tpm2.TPMAlgNull}}),
		Unique: tpm2.NewTPMUPublicID(tpm2.TPMAlgKeyedHash, &tpm2.TPM2BDigest{}),
	}
}

// SealSeed seals seed under the storage primary and records the blobs in md.
// Like the ECDH results, the seed crosses the TPM interface without parameter
// encryption: the host uses it in memory anyway, and the sealed blob is what
// keeps it bound to this TPM at rest.
func (b *TPMBackend) SealSeed(md *Metadata, seed []byte) error {
	if len(seed) != mlkem.SeedSize {
		return errors.New("ML-KEM seed must be 64 bytes")
	}
	t, parent, err := b.primary()
	if err != nil {
		return err
	}
	defer func() { _ = t.Close() }()
	defer func() { _ = flush(t, parent.ObjectHandle) }()
	created, err := (tpm2.Create{
		ParentHandle: tpm2.AuthHandle{Handle: parent.ObjectHandle, Name: parent.Name,
			Auth: tpm2.HMAC(tpm2.TPMAlgSHA256, 16)},
		InSensitive: tpm2.TPM2BSensitiveCreate{Sensitive: &tpm2.TPMSSensitiveCreate{
			Data: tpm2.NewTPMUSensitiveCreate(&tpm2.TPM2BSensitiveData{Buffer: seed})}},
		InPublic: tpm2.New2B(sealTemplate()),
	}).Execute(t)
	if err != nil {
		return fmt.Errorf("sealing ML-KEM seed: %w", err)
	}
	md.TPMSealPublic = tpm2.Marshal(created.OutPublic)
	md.TPMSealPrivate = tpm2.Marshal(created.OutPrivate)
	return nil
}

// UnsealSeed loads the sealed object recorded in md and returns the seed. The
// object must match sealTemplate, so a blob with other attributes is refused.
func (b *TPMBackend) UnsealSeed(md *Metadata) ([]byte, error) {
	public, err := tpm2.Unmarshal[tpm2.TPM2BPublic](md.TPMSealPublic)
	if err != nil {
		return nil, fmt.Errorf("sealed seed public blob: %w", err)
	}
	private, err := tpm2.Unmarshal[tpm2.TPM2BPrivate](md.TPMSealPrivate)
	if err != nil {
		return nil, fmt.Errorf("sealed seed private blob: %w", err)
	}
	pub, err := public.Contents()
	if err != nil {
		return nil, err
	}
	expected := sealTemplate()
	expected.Unique = pub.Unique
	if !bytes.Equal(tpm2.Marshal(expected), tpm2.Marshal(*pub)) {
		return nil, errors.New("sealed seed does not match the sealed-data template")
	}
	t, parent, err := b.primary()
	if err != nil {
		return nil, err
	}
	defer func() { _ = t.Close() }()
	defer func() { _ = flush(t, parent.ObjectHandle) }()
	loaded, err := (tpm2.Load{ParentHandle: tpm2.AuthHandle{Handle: parent.ObjectHandle, Name: parent.Name, Auth: tpm2.HMAC(tpm2.TPMAlgSHA256, 16)},
		InPublic: *public, InPrivate: *private}).Execute(t)
	if err != nil {
		return nil, fmt.Errorf("loading sealed seed: %w", err)
	}
	defer func() { _ = flush(t, loaded.ObjectHandle) }()
	rsp, err := (tpm2.Unseal{ItemHandle: tpm2.AuthHandle{Handle: loaded.ObjectHandle, Name: loaded.Name,
		Auth: tpm2.HMAC(tpm2.TPMAlgSHA256, 16)}}).Execute(t)
	if err != nil {
		return nil, fmt.Errorf("unsealing ML-KEM seed: %w", err)
	}
	if len(rsp.OutData.Buffer) != mlkem.SeedSize {
		clear(rsp.OutData.Buffer)
		return nil, errors.New("sealed ML-KEM seed has the wrong size")
	}
	// The caller owns the response buffer and clears it once the key is derived.
	return rsp.OutData.Buffer, nil
}
