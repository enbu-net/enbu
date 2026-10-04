package artifact

import "testing"

func FuzzDecodeArtifact(f *testing.F) {
	seed, err := EncodeArtifact(validArtifact())
	if err != nil {
		f.Fatalf("seed: %v", err)
	}
	f.Add(seed)
	f.Add([]byte{0xff})

	f.Fuzz(func(t *testing.T, data []byte) {
		artifact, err := DecodeArtifact(data)
		if err != nil {
			return
		}
		encoded, err := EncodeArtifact(artifact)
		if err != nil {
			t.Fatalf("accepted artifact no longer encodes: %v", err)
		}
		if string(encoded) != string(data) {
			t.Fatal("accepted non-canonical representation")
		}
	})
}
