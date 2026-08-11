package artifact

import (
	"bytes"
	"encoding/hex"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/opencontainers/go-digest"
)

func TestRevisionCanonicalEncoding(t *testing.T) {
	t.Parallel()

	first := validResource()
	first.Payloads = append(first.Payloads, PayloadRef{
		Name:      "alpha",
		MediaType: "text/plain",
		Digest:    digest.FromString("alpha"),
		Size:      5,
	})
	first.Edges = []Edge{
		{
			ID:       "55555555-5555-4555-8555-555555555555",
			Name:     "second",
			Relation: TypeRef{Group: "example.com", Version: "v1", Kind: "Related"},
			Strength: EdgeLogical,
			Target:   "66666666-6666-4666-8666-666666666666",
		},
		{
			ID:       "44444444-4444-4444-8444-444444444444",
			Name:     "first",
			Relation: TypeRef{Group: "example.com", Version: "v1", Kind: "Related"},
			Strength: EdgeLogical,
			Target:   "77777777-7777-4777-8777-777777777777",
		},
	}
	second := first
	second.Payloads = []PayloadRef{first.Payloads[1], first.Payloads[0]}
	second.Edges = []Edge{first.Edges[1], first.Edges[0]}

	firstBytes, err := EncodeRevision(first)
	if err != nil {
		t.Fatalf("EncodeRevision(first): %v", err)
	}
	secondBytes, err := EncodeRevision(second)
	if err != nil {
		t.Fatalf("EncodeRevision(second): %v", err)
	}
	if !bytes.Equal(firstBytes, secondBytes) {
		t.Fatal("set order changed canonical encoding")
	}
	if first.Payloads[0].Name != "content" || first.Edges[0].Name != "second" {
		t.Fatal("EncodeRevision mutated its input")
	}

	decoded, err := DecodeRevision(firstBytes)
	if err != nil {
		t.Fatalf("DecodeRevision: %v", err)
	}
	if decoded.Payloads[0].Name != "alpha" || decoded.Edges[0].Name != "first" {
		t.Fatalf("decoded canonical order = payload %q, edge %q", decoded.Payloads[0].Name, decoded.Edges[0].Name)
	}
}

func TestDecodeRevisionRejectsNonCanonicalAndUnknownFields(t *testing.T) {
	t.Parallel()

	revision := validResource()
	canonical, err := EncodeRevision(revision)
	if err != nil {
		t.Fatalf("EncodeRevision: %v", err)
	}

	nonCanonicalMode, err := cbor.EncOptions{Sort: cbor.SortNone}.EncMode()
	if err != nil {
		t.Fatalf("create non-canonical encoder: %v", err)
	}
	nonCanonical, err := nonCanonicalMode.Marshal(revision)
	if err != nil {
		t.Fatalf("encode non-canonical: %v", err)
	}
	if bytes.Equal(nonCanonical, canonical) {
		t.Skip("fixture happened to use canonical map order")
	}
	if _, err := DecodeRevision(nonCanonical); !errors.Is(err, ErrNonCanonicalEncoding) {
		t.Fatalf("DecodeRevision(non-canonical) = %v, want ErrNonCanonicalEncoding", err)
	}

	var object map[string]any
	if err := UnmarshalStrict(canonical, &object); err != nil {
		t.Fatalf("decode fixture to map: %v", err)
	}
	object["futureField"] = "not accepted in v1alpha1"
	withUnknown, err := MarshalCanonical(object)
	if err != nil {
		t.Fatalf("encode unknown field: %v", err)
	}
	if _, err := DecodeRevision(withUnknown); err == nil {
		t.Fatal("DecodeRevision accepted an unknown field")
	}
}

func TestDecodeRevisionRejectsOversizedInputBeforeDecode(t *testing.T) {
	t.Parallel()

	oversized := make([]byte, MaxRevisionBytes+1)
	if _, err := DecodeRevision(oversized); !errors.Is(err, ErrInvalidArtifact) || !strings.Contains(err.Error(), "revision exceeds") {
		t.Fatalf("DecodeRevision(oversized) = %v, want revision size-limit error", err)
	}
}

func TestUnmarshalStrictRejectsMalformedAndDuplicateMaps(t *testing.T) {
	t.Parallel()

	canonical, err := EncodeRevision(validResource())
	if err != nil {
		t.Fatalf("EncodeRevision: %v", err)
	}
	if _, err := DecodeRevision(canonical[:len(canonical)-1]); err == nil {
		t.Fatal("DecodeRevision accepted truncated CBOR")
	}

	duplicateName := []byte{
		0xa2,
		0x64, 'n', 'a', 'm', 'e', 0x61, 'a',
		0x64, 'n', 'a', 'm', 'e', 0x61, 'b',
	}
	var target struct {
		Name string `cbor:"name"`
	}
	if err := UnmarshalStrict(duplicateName, &target); err == nil {
		t.Fatal("UnmarshalStrict accepted a duplicate map key")
	}
}

func TestCanonicalCodecRejectsUnsupportedWireValues(t *testing.T) {
	t.Parallel()

	for name, value := range map[string]any{
		"float":        map[string]any{"value": 1.5},
		"integer key":  map[int]string{1: "value"},
		"non NFC text": map[string]string{"value": "e\u0301"},
	} {
		if _, err := MarshalCanonical(value); !errors.Is(err, ErrInvalidArtifact) {
			t.Errorf("%s: MarshalCanonical error = %v, want ErrInvalidArtifact", name, err)
		}
	}

	var decoded any
	if err := UnmarshalStrict([]byte{0xfb, 0x3f, 0xf8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, &decoded); !errors.Is(err, ErrInvalidArtifact) {
		t.Fatalf("UnmarshalStrict(float) = %v, want ErrInvalidArtifact", err)
	}
}

func TestUnknownCustomSchemaRoundTrip(t *testing.T) {
	t.Parallel()

	want := validResource()
	want.Schema = TypeRef{Group: "customer.example", Version: "v7beta2", Kind: "HardwareCredential"}
	want.Metadata.Annotations["customer.example/format"] = "vendor-specific-v3"

	encoded, err := EncodeRevision(want)
	if err != nil {
		t.Fatalf("EncodeRevision: %v", err)
	}
	got, err := DecodeRevision(encoded)
	if err != nil {
		t.Fatalf("DecodeRevision: %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("custom schema round-trip changed value\n got: %#v\nwant: %#v", got, want)
	}
}

func TestRevisionGoldenVector(t *testing.T) {
	t.Parallel()

	data, err := EncodeRevision(validResource())
	if err != nil {
		t.Fatalf("EncodeRevision: %v", err)
	}
	wantHexBytes, err := os.ReadFile("testdata/resource-v1.cbor.hex")
	if err != nil {
		t.Fatalf("read golden CBOR: %v", err)
	}
	wantHex := strings.TrimSpace(string(wantHexBytes))
	if got := hex.EncodeToString(data); got != wantHex {
		t.Fatalf("canonical CBOR changed\n got: %s\nwant: %s", got, wantHex)
	}
	wantDigestBytes, err := os.ReadFile("testdata/resource-v1.digest")
	if err != nil {
		t.Fatalf("read golden digest: %v", err)
	}
	wantDigest := strings.TrimSpace(string(wantDigestBytes))
	if got := digest.FromBytes(data).String(); got != wantDigest {
		t.Fatalf("digest = %s, want %s", got, wantDigest)
	}
}
