package cas

import (
	"testing"

	"github.com/enbu-net/enbu/pkg/artifact"
	"github.com/opencontainers/go-digest"
)

func FuzzDecodeDescriptor(f *testing.F) {
	valid, err := encodeDescriptor(artifact.Descriptor{
		MediaType: "application/octet-stream",
		Digest:    digest.FromBytes([]byte("seed")),
		Size:      4,
	})
	if err != nil {
		f.Fatal(err)
	}
	f.Add(valid)
	f.Add([]byte{})
	f.Add([]byte{0xff, 0x01})

	f.Fuzz(func(t *testing.T, encoded []byte) {
		descriptor, err := decodeDescriptor(encoded)
		if err != nil {
			return
		}
		reencoded, err := encodeDescriptor(descriptor)
		if err != nil {
			t.Fatalf("accepted descriptor cannot be encoded: %v", err)
		}
		if string(encoded) != string(reencoded) {
			t.Fatal("accepted descriptor was not canonical")
		}
	})
}
