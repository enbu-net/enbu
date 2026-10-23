package age

import (
	"filippo.io/age"
)

type KeyPair struct {
	Identity  *age.X25519Identity
	PublicKey string
}

func GenerateKeyPair() (*KeyPair, error) {
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		return nil, err
	}
	return &KeyPair{
		Identity:  identity,
		PublicKey: identity.Recipient().String(),
	}, nil
}

type HybridKeyPair struct {
	Identity  *age.HybridIdentity
	PublicKey string
}

// GenerateHybridKeyPair generates an ML-KEM-768 + X25519 (X-Wing) identity.
func GenerateHybridKeyPair() (*HybridKeyPair, error) {
	identity, err := age.GenerateHybridIdentity()
	if err != nil {
		return nil, err
	}
	return &HybridKeyPair{
		Identity:  identity,
		PublicKey: identity.Recipient().String(),
	}, nil
}
