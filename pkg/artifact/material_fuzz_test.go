package artifact

import (
	"bytes"
	"testing"

	"github.com/opencontainers/go-digest"
)

func FuzzMaterialManifestCanonical(f *testing.F) {
	identity, err := GenerateMaterialIdentity()
	if err != nil {
		f.Fatalf("GenerateMaterialIdentity: %v", err)
	}
	emptyDigest := digest.FromBytes(nil)
	manifest := MaterialManifest{
		APIVersion: APIVersion,
		Recipient:  identity.RecipientString(),
		Revision: EncryptedStream{
			Digest: emptyDigest,
			Chunks: []ChunkRef{{
				Ciphertext: Descriptor{
					MediaType: MediaTypeEncryptedChunk,
					Digest:    digest.FromString("ciphertext"),
					Size:      1,
				},
			}},
		},
	}
	seed, err := EncodeMaterialManifest(manifest)
	if err != nil {
		f.Fatalf("EncodeMaterialManifest: %v", err)
	}
	f.Add(seed)

	f.Fuzz(func(t *testing.T, data []byte) {
		manifest, err := DecodeMaterialManifest(data)
		if err != nil {
			return
		}
		canonical, err := EncodeMaterialManifest(manifest)
		if err != nil {
			t.Fatalf("accepted manifest did not re-encode: %v", err)
		}
		if !bytes.Equal(data, canonical) {
			t.Fatal("accepted manifest was not canonical")
		}
	})
}
