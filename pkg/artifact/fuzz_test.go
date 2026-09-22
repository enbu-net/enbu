package artifact

import "testing"

func FuzzDecodeRevision(f *testing.F) {
	seed, err := EncodeRevision(validResource())
	if err != nil {
		f.Fatalf("seed: %v", err)
	}
	f.Add(seed)
	f.Add([]byte{0xff})

	f.Fuzz(func(t *testing.T, data []byte) {
		revision, err := DecodeRevision(data)
		if err != nil {
			return
		}
		encoded, err := EncodeRevision(revision)
		if err != nil {
			t.Fatalf("accepted revision no longer encodes: %v", err)
		}
		if string(encoded) != string(data) {
			t.Fatal("accepted non-canonical representation")
		}
	})
}
