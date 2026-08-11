package commit

import (
	"bytes"
	"testing"
)

func FuzzDecodeSignedCommit(f *testing.F) {
	signer := newTestSigner(2, 7)
	valid, err := SignCommit(baseCommit(0, nil), signer, authorFor(f, signer))
	if err != nil {
		f.Fatalf("SignCommit seed: %v", err)
	}
	f.Add(valid)
	f.Add([]byte{0xa0})
	f.Add([]byte("not-cbor"))

	f.Fuzz(func(t *testing.T, data []byte) {
		decoded, decodeErr := DecodeSignedCommit(data)
		if decodeErr != nil {
			return
		}
		reencoded, encodeErr := EncodeSignedCommit(decoded)
		if encodeErr != nil {
			t.Fatalf("successful decode did not re-encode: %v", encodeErr)
		}
		if !bytes.Equal(data, reencoded) {
			t.Fatal("successful decode did not preserve canonical bytes")
		}
	})
}

func FuzzParseTimestamp(f *testing.F) {
	f.Add("2026-08-08T03:34:56.000000123Z")
	f.Add("2026-08-08T03:34:56Z")
	f.Add("")
	f.Fuzz(func(t *testing.T, value string) {
		parsed, err := ParseTimestamp(value)
		if err == nil && string(parsed) != value {
			t.Fatalf("ParseTimestamp changed accepted value %q to %q", value, parsed)
		}
	})
}
