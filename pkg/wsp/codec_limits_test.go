package wsp

import (
	"bytes"
	"errors"
	"testing"
)

func TestCanonicalDecoderResourceBoundaries(t *testing.T) {
	nested := func(depth int) any {
		var value any = uint64(0)
		for range depth {
			value = []any{value}
		}
		return value
	}
	mapOf := func(count int) any {
		value := map[uint64]uint64{}
		for i := range count {
			value[uint64(i)] = uint64(i)
		}
		return value
	}
	for _, tc := range []struct {
		name  string
		value any
		valid bool
	}{
		{"nested-exact", nested(8), true},
		{"nested-over", nested(9), false},
		{"array-exact", make([]uint64, 4096), true},
		{"array-over", make([]uint64, 4097), false},
		{"map-exact", mapOf(64), true},
		{"map-over", mapOf(65), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data, err := encMode.Marshal(tc.value)
			if err != nil {
				t.Fatal(err)
			}
			var got any
			err = decodeCanonical(data, &got)
			if tc.valid && err != nil || !tc.valid && !errors.Is(err, ErrInvalid) {
				t.Fatalf("decoder boundary valid=%t err=%v", tc.valid, err)
			}
		})
	}
}

func TestSignedEnvelopeSizeBoundary(t *testing.T) {
	// Determine the exact body budget from the fixed envelope overhead rather
	// than assuming the byte-string header width at the one-megabyte boundary.
	body := bytes.Repeat([]byte{0}, MaxSignedBytes)
	for {
		data, err := (Signed{Body: body, Signature: []byte{1}}).Encode()
		if err != nil {
			t.Fatal(err)
		}
		if len(data) > MaxSignedBytes {
			body = body[:len(body)-(len(data)-MaxSignedBytes)]
			continue
		}
		if len(data) != MaxSignedBytes {
			t.Fatalf("fixture did not reach exact signed limit: %d", len(data))
		}
		if _, err := DecodeSigned(data); err != nil {
			t.Fatalf("exact signed limit rejected: %v", err)
		}
		oversized, err := (Signed{Body: append(body, 0), Signature: []byte{1}}).Encode()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := DecodeSigned(oversized); !errors.Is(err, ErrInvalid) {
			t.Fatalf("oversized signed object accepted: %v", err)
		}
		break
	}
}
