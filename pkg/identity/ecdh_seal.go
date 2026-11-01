package identity

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"errors"

	hpkeecdh "filippo.io/hpke/crypto/ecdh"
)

// ecdhSealInfo separates the seal key from every other use of the device key.
const ecdhSealInfo = "enbu identity ML-KEM seed seal v1"

// sealToECDH encrypts secret to a P-256 public key, so that only the holder of
// the private key can open it. It is ECIES: an ephemeral ECDH share, HKDF-SHA256
// bound to both public keys, and AES-256-GCM. A backend whose hardware key can
// only run ECDH (the Secure Enclave) uses it to keep the ML-KEM seed bound to
// the device. The result is the ephemeral public key followed by the ciphertext.
func sealToECDH(pub *ecdh.PublicKey, secret []byte) ([]byte, error) {
	if pub == nil || pub.Curve() != ecdh.P256() {
		return nil, errors.New("seal requires a P-256 public key")
	}
	eph, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	shared, err := eph.ECDH(pub)
	if err != nil {
		return nil, err
	}
	aead, err := sealAEAD(shared, eph.PublicKey().Bytes(), pub.Bytes())
	clear(shared)
	if err != nil {
		return nil, err
	}
	share := eph.PublicKey().Bytes()
	// The key is unique to this ephemeral share, so a zero nonce is safe.
	return aead.Seal(share, make([]byte, aead.NonceSize()), secret, nil), nil
}

// openFromECDH reverses sealToECDH with the private key behind k.
func openFromECDH(k hpkeecdh.KeyExchanger, sealed []byte) ([]byte, error) {
	pub := k.PublicKey()
	if pub == nil || pub.Curve() != ecdh.P256() {
		return nil, errors.New("seal requires a P-256 key")
	}
	const shareSize = 65
	if len(sealed) <= shareSize {
		return nil, errors.New("sealed data is too short")
	}
	eph, err := ecdh.P256().NewPublicKey(sealed[:shareSize])
	if err != nil {
		return nil, errors.New("sealed data has an invalid key share")
	}
	shared, err := k.ECDH(eph)
	if err != nil {
		return nil, err
	}
	aead, err := sealAEAD(shared, eph.Bytes(), pub.Bytes())
	clear(shared)
	if err != nil {
		return nil, err
	}
	out, err := aead.Open(nil, make([]byte, aead.NonceSize()), sealed[shareSize:], nil)
	if err != nil {
		return nil, errors.New("sealed data does not open with this device key")
	}
	return out, nil
}

func sealAEAD(shared, share, recipient []byte) (cipher.AEAD, error) {
	salt := append(append([]byte(nil), share...), recipient...)
	key, err := hkdf.Key(sha256.New, shared, salt, ecdhSealInfo, 32)
	if err != nil {
		return nil, err
	}
	defer clear(key)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}
