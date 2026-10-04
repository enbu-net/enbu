package artifact

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/opencontainers/go-digest"
)

func TestArtifactDeterminismAndMutationSafety(t *testing.T) {
	t.Parallel()
	a := validArtifact()
	a.Payloads = append(a.Payloads, PayloadRef{Name: "alpha", MediaType: "text/plain", Digest: digest.FromString("alpha"), Size: 5})
	a.Metadata.Labels["a"] = "first"
	a.Metadata.Annotations["a"] = "first"
	before := validArtifact()
	before.Payloads = append(before.Payloads, a.Payloads[1])
	before.Metadata.Labels["a"] = "first"
	before.Metadata.Annotations["a"] = "first"
	b := a
	b.Payloads = []PayloadRef{a.Payloads[1], a.Payloads[0]}
	b.Metadata.Labels = map[string]string{}
	b.Metadata.Labels["a"] = "first"
	b.Metadata.Labels["example.com/tier"] = "backend"
	b.Metadata.Annotations = map[string]string{}
	b.Metadata.Annotations["a"] = "first"
	b.Metadata.Annotations["description"] = "integration fixture"
	first, err := CanonicalDigest(a)
	if err != nil {
		t.Fatal(err)
	}
	second, err := CanonicalDigest(b)
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatal("map insertion or payload order changed digest")
	}
	if !reflect.DeepEqual(a, before) {
		t.Fatal("encoding mutated caller data")
	}
	encoded, err := EncodeArtifact(a)
	if err != nil {
		t.Fatal(err)
	}
	if first != digest.FromBytes(encoded) {
		t.Fatal("digest differs from encoded bytes")
	}
	got, err := DecodeArtifact(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, b) {
		t.Fatalf("round trip = %#v, want %#v", got, b)
	}
}

func TestArtifactEmptyValues(t *testing.T) {
	t.Parallel()
	a := validArtifact()
	a.Metadata.Labels = nil
	a.Metadata.Annotations = nil
	a.Payloads = nil
	data, err := EncodeArtifact(a)
	if err != nil {
		t.Fatal(err)
	}
	if a.Payloads != nil || a.Metadata.Labels != nil || a.Metadata.Annotations != nil {
		t.Fatal("mutated nil values")
	}
	b := a
	b.Payloads = []PayloadRef{}
	b.Metadata.Labels = map[string]string{}
	b.Metadata.Annotations = map[string]string{}
	empty, err := EncodeArtifact(b)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, empty) {
		t.Fatal("nil and empty differ")
	}
	got, err := DecodeArtifact(data)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, b) {
		t.Fatalf("empty round trip: %#v", got)
	}
}

func TestDecodeArtifactRejectsWireValues(t *testing.T) {
	t.Parallel()
	canonical, err := EncodeArtifact(validArtifact())
	if err != nil {
		t.Fatal(err)
	}
	// Mutate the wire object so invalid fields bypass the encoder's validation.
	object := func() map[string]any {
		var m map[string]any
		if err := cbor.Unmarshal(canonical, &m); err != nil {
			t.Fatal(err)
		}
		return m
	}
	encode := func(v any) []byte {
		data, err := canonicalEncMode.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	reject := func(t *testing.T, data []byte, want error) {
		t.Helper()
		_, err := DecodeArtifact(data)
		if err == nil || (want != nil && !errors.Is(err, want)) {
			t.Fatalf("decode error = %v, want %v", err, want)
		}
	}
	for name, data := range map[string][]byte{
		"truncated":         canonical[:len(canonical)-1],
		"trailing":          append(append([]byte{}, canonical...), 0),
		"indefinite":        append(append([]byte{0xbf}, canonical[1:]...), 0xff),
		"tag":               append([]byte{0xc0}, canonical...),
		"duplicate map key": append(append(append([]byte{0xa6}, canonical[1:]...), 0x63, 'u', 'i', 'd'), encode(string(testArtifactUID))...),
		"deep nesting":      append(bytes.Repeat([]byte{0x81}, 33), 0),
		"map pair limit":    {0xb9, 0x10, 0x01},
		"array count limit": {0x99, 0x04, 0x01},
	} {
		t.Run(name, func(t *testing.T) { reject(t, data, nil) })
	}
	for name, mutate := range map[string]func(map[string]any){
		"unknown top field":    func(m map[string]any) { m["future"] = "value" },
		"unknown nested field": func(m map[string]any) { m["schema"].(map[any]any)["future"] = "value" },
		"float":                func(m map[string]any) { m["payloads"].([]any)[0].(map[any]any)["size"] = 9.0 },
		"negative size":        func(m map[string]any) { m["payloads"].([]any)[0].(map[any]any)["size"] = -1 },
		"null size":            func(m map[string]any) { m["payloads"].([]any)[0].(map[any]any)["size"] = nil },
		"null labels":          func(m map[string]any) { m["metadata"].(map[any]any)["labels"] = nil },
		"null annotations":     func(m map[string]any) { m["metadata"].(map[any]any)["annotations"] = nil },
		"null payloads":        func(m map[string]any) { m["payloads"] = nil },
		"null map key":         func(m map[string]any) { m["metadata"].(map[any]any)["labels"] = map[any]any{nil: "a"} },
		"invalid UTF8":         func(m map[string]any) { m["metadata"].(map[any]any)["name"] = string([]byte{0xff}) },
		"non NFC": func(m map[string]any) {
			m["metadata"].(map[any]any)["annotations"] = map[string]string{"note": "e\u0301"}
		},
		"unsupported API":   func(m map[string]any) { m["apiVersion"] = "artifacts.enbu.net/v1alpha1" },
		"noncanonical UUID": func(m map[string]any) { m["uid"] = "11111111-1111-4111-8111-11111111111A" },
		"sha512": func(m map[string]any) {
			m["payloads"].([]any)[0].(map[any]any)["digest"] = "sha512:" + strings.Repeat("a", 128)
		},
		"uppercase digest": func(m map[string]any) {
			m["payloads"].([]any)[0].(map[any]any)["digest"] = "sha256:" + strings.Repeat("A", 64)
		},
		"short digest":      func(m map[string]any) { m["payloads"].([]any)[0].(map[any]any)["digest"] = "sha256:abc" },
		"duplicate payload": func(m map[string]any) { p := m["payloads"].([]any); m["payloads"] = append(p, p[0]) },
		"metadata bytes": func(m map[string]any) {
			m["metadata"].(map[any]any)["annotations"] = map[string]string{"note": strings.Repeat("a", MaxMetadataBytes)}
		},
		"metadata entries": func(m map[string]any) {
			labels := map[string]string{}
			for i := range MaxMetadataEntries {
				labels[fmt.Sprintf("k%d", i)] = ""
			}
			m["metadata"].(map[any]any)["labels"] = labels
		},
		"payload count": func(m map[string]any) {
			p := m["payloads"].([]any)[0]
			list := make([]any, MaxPayloads+1)
			for i := range list {
				list[i] = p
			}
			m["payloads"] = list
		},
	} {
		t.Run(name, func(t *testing.T) { m := object(); mutate(m); reject(t, encode(m), nil) })
	}
	for name, mutate := range map[string]func(map[string]any){
		"omitted labels":      func(m map[string]any) { delete(m["metadata"].(map[any]any), "labels") },
		"omitted annotations": func(m map[string]any) { delete(m["metadata"].(map[any]any), "annotations") },
		"omitted payloads":    func(m map[string]any) { delete(m, "payloads") },
		"omitted size":        func(m map[string]any) { delete(m["payloads"].([]any)[0].(map[any]any), "size") },
		"payload order": func(m map[string]any) {
			p := m["payloads"].([]any)
			m["payloads"] = append(p, map[string]any{"name": "alpha", "mediaType": "text/plain", "digest": digest.FromString("a").String(), "size": uint64(1)})
		},
	} {
		t.Run(name, func(t *testing.T) { m := object(); mutate(m); reject(t, encode(m), ErrNonCanonicalEncoding) })
	}
	t.Run("map order", func(t *testing.T) {
		mode, err := (cbor.EncOptions{Sort: cbor.SortNone}).EncMode()
		if err != nil {
			t.Fatal(err)
		}
		data, err := mode.Marshal(validArtifact())
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Equal(data, canonical) {
			t.Fatal("fixture must have different map order")
		}
		reject(t, data, ErrNonCanonicalEncoding)
	})
	t.Run("integer encoding", func(t *testing.T) {
		m := object()
		m["payloads"].([]any)[0].(map[any]any)["size"] = cbor.RawMessage{0x18, 0x09}
		reject(t, encode(m), ErrNonCanonicalEncoding)
	})
	t.Run("oversized artifact", func(t *testing.T) { reject(t, make([]byte, MaxArtifactBytes+1), ErrInvalidArtifact) })
}

func TestArtifactValidation(t *testing.T) {
	t.Parallel()
	for name, mutate := range map[string]func(*Artifact){
		"version":           func(a *Artifact) { a.APIVersion = "v2" },
		"UID":               func(a *Artifact) { a.UID = "invalid" },
		"schema":            func(a *Artifact) { a.Schema.Version = "v0" },
		"metadata":          func(a *Artifact) { a.Metadata.Name = "" },
		"payload":           func(a *Artifact) { a.Payloads[0].Name = "" },
		"payload count":     func(a *Artifact) { a.Payloads = make([]PayloadRef, MaxPayloads+1) },
		"duplicate payload": func(a *Artifact) { a.Payloads = append(a.Payloads, a.Payloads[0]) },
	} {
		t.Run(name, func(t *testing.T) {
			a := validArtifact()
			mutate(&a)
			if err := a.Validate(); !errors.Is(err, ErrInvalidArtifact) {
				t.Fatalf("Validate: %v", err)
			}
			if _, err := EncodeArtifact(a); !errors.Is(err, ErrInvalidArtifact) {
				t.Fatalf("Encode: %v", err)
			}
			if _, err := CanonicalDigest(a); !errors.Is(err, ErrInvalidArtifact) {
				t.Fatalf("Digest: %v", err)
			}
		})
	}
	t.Run("uint64 size", func(t *testing.T) {
		a := validArtifact()
		a.Payloads[0].Size = math.MaxUint64
		data, err := EncodeArtifact(a)
		if err != nil {
			t.Fatal(err)
		}
		got, err := DecodeArtifact(data)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(got, a) {
			t.Fatal("large plaintext size failed round trip")
		}
	})
}

func TestArtifactEncodedSizeLimit(t *testing.T) {
	t.Parallel()
	a := validArtifact()
	a.Payloads = nil
	for i := range 65 {
		a.Payloads = append(a.Payloads, PayloadRef{
			Name:      fmt.Sprintf("p%d", i),
			MediaType: "text/plain; note=" + strings.Repeat("a", MaxMetadataBytes-17),
			Digest:    digest.FromString("content"),
		})
	}
	if err := a.Validate(); err != nil {
		t.Fatal(err)
	}
	if _, err := EncodeArtifact(a); !errors.Is(err, ErrInvalidArtifact) {
		t.Fatalf("oversized encode = %v", err)
	}
}

func TestArtifactPayloadCountBoundary(t *testing.T) {
	t.Parallel()
	a := validArtifact()
	p := a.Payloads[0]
	a.Payloads = nil
	for i := range MaxPayloads {
		p.Name = fmt.Sprintf("p%04d", i)
		a.Payloads = append(a.Payloads, p)
	}
	data, err := EncodeArtifact(a)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeArtifact(data)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, a) {
		t.Fatal("payload limit round trip changed data")
	}
}

func TestUnknownCustomSchemaRoundTrip(t *testing.T) {
	t.Parallel()

	want := validArtifact()
	want.Schema = TypeRef{Group: "customer.example", Version: "v7beta2", Kind: "HardwareCredential"}
	want.Metadata.Annotations["customer.example/format"] = "vendor-specific-v3"
	want.Metadata.Labels["enbu.net/authorization"] = "admin"
	want.Metadata.Annotations["enbu.net/plugin"] = "https://example.com/plugin.wasm"
	want.Metadata.Annotations["enbu.net/destination"] = "/tmp/example"

	encoded, err := EncodeArtifact(want)
	if err != nil {
		t.Fatalf("EncodeArtifact: %v", err)
	}
	got, err := DecodeArtifact(encoded)
	if err != nil {
		t.Fatalf("DecodeArtifact: %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("custom schema round-trip changed value\n got: %#v\nwant: %#v", got, want)
	}
}

func TestArtifactGoldenVector(t *testing.T) {
	t.Parallel()

	// These fixtures were constructed independently using RFC 8949 major types
	// and bytewise ordering of encoded keys, not generated by EncodeArtifact.
	// Updating them requires an explicit wire-format decision.
	data, err := EncodeArtifact(validArtifact())
	if err != nil {
		t.Fatalf("EncodeArtifact: %v", err)
	}
	wantHexBytes, err := os.ReadFile("testdata/artifact-v2.cbor.hex")
	if err != nil {
		t.Fatalf("read golden CBOR: %v", err)
	}
	wantHex := strings.TrimSpace(string(wantHexBytes))
	if got := hex.EncodeToString(data); got != wantHex {
		t.Fatalf("canonical CBOR changed\n got: %s\nwant: %s", got, wantHex)
	}
	wantDigestBytes, err := os.ReadFile("testdata/artifact-v2.digest")
	if err != nil {
		t.Fatalf("read golden digest: %v", err)
	}
	wantDigest := strings.TrimSpace(string(wantDigestBytes))
	gotDigest, err := CanonicalDigest(validArtifact())
	if err != nil {
		t.Fatal(err)
	}
	if got := gotDigest.String(); got != wantDigest {
		t.Fatalf("digest = %s, want %s", got, wantDigest)
	}
}
