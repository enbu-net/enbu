package wsp

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"filippo.io/age"
	"github.com/enbu-net/enbu/pkg/signing"
)

const testWorkspace = "0192f3a0-7c1e-7a55-9d3c-5f6a1b2c3d4e"

type actor struct {
	signer signing.Signer
	p      Principal
}

func newActor(t *testing.T, admin bool) actor {
	t.Helper()
	_, k, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s := signing.NewEd25519Signer(k)
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	return actor{signer: s, p: Principal{ID: s.Public().DeviceID(), Signing: s.Public(), Recipient: id.Recipient().String(), Admin: admin}}
}
