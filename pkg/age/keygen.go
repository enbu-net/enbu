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
