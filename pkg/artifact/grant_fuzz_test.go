package artifact

import (
	"bytes"
	"testing"

	"github.com/opencontainers/go-digest"
)

func FuzzAccessGrantCanonical(f *testing.F) {
	body := []byte("encrypted-claims")
	wrap := []byte("anonymous-encrypted-wrap")
	seed, err := EncodeAccessGrant(AccessGrant{
		APIVersion:     AccessGrantAPIVersion,
		Kind:           AccessGrantKind,
		Material:       digest.FromString("material"),
		BodyDigest:     digest.FromString("claims"),
		BodyCiphertext: body,
		Wraps: []IdentityWrap{{
			Digest:     digest.FromBytes(wrap),
			Ciphertext: wrap,
		}},
	})
	if err != nil {
		f.Fatalf("EncodeAccessGrant: %v", err)
	}
	f.Add(seed)

	f.Fuzz(func(t *testing.T, data []byte) {
		grant, err := DecodeAccessGrant(data)
		if err != nil {
			return
		}
		canonical, err := EncodeAccessGrant(grant)
		if err != nil {
			t.Fatalf("accepted Grant did not re-encode: %v", err)
		}
		if !bytes.Equal(data, canonical) {
			t.Fatal("accepted Grant was not canonical")
		}
	})
}
