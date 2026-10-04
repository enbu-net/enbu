package secretmap

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
	"testing"

	"github.com/enbu-net/enbu/pkg/artifact"
	"github.com/enbu-net/enbu/pkg/content"
	"github.com/fxamacker/cbor/v2"
	"github.com/opencontainers/go-digest"
)

func TestCanonicalPayload(t *testing.T) {
	t.Parallel()
	want := SecretMap{"TOKEN": "abc", "API_KEY": "secret", "UNICODE": "e\u0301", "SPACE": "  \t\n"}
	a, err := Encode(want)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Decode(a)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("round trip changed secrets: %#v", got)
	}
	reordered := SecretMap{}
	for _, key := range []string{"UNICODE", "SPACE", "TOKEN", "API_KEY"} {
		reordered[key] = want[key]
	}
	b, err := Encode(reordered)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, b) {
		t.Fatal("map order changed canonical payload")
	}
	if !reflect.DeepEqual(want, SecretMap{"TOKEN": "abc", "API_KEY": "secret", "UNICODE": "e\u0301", "SPACE": "  \t\n"}) {
		t.Fatal("encoder mutated input")
	}
	for _, empty := range []SecretMap{nil, {}} {
		data, err := Encode(empty)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(data, []byte{0xa0}) {
			t.Fatal("empty map is not canonical")
		}
		decoded, err := Decode(data)
		if err != nil || decoded == nil || len(decoded) != 0 {
			t.Fatalf("empty decode = %#v, %v", decoded, err)
		}
	}
}

func TestSecretMapGolden(t *testing.T) {
	t.Parallel()
	// Fixed RFC 8949 map: encoded text keys sort A before BB, independently of Go.
	const golden = "a26141617862424262797a"
	data, err := Encode(SecretMap{"BB": "yz", "A": "x"})
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(data) != golden {
		t.Fatalf("wire changed: %x", data)
	}
}

func TestDecodeRejectsMalformedPayload(t *testing.T) {
	t.Parallel()
	for name, data := range map[string][]byte{
		"empty":                  nil,
		"duplicate keys":         {0xa2, 0x61, 'A', 0x61, 'x', 0x61, 'A', 0x61, 'y'},
		"indefinite":             {0xbf, 0x61, 'A', 0x61, 'x', 0xff},
		"tag":                    {0xc0, 0xa0},
		"null":                   {0xf6},
		"null value":             {0xa1, 0x61, 'A', 0xf6},
		"float":                  {0xa1, 0x61, 'A', 0xf9, 0x3c, 0x00},
		"invalid UTF8":           {0xa1, 0x61, 'A', 0x61, 0xff},
		"byte string":            {0xa1, 0x61, 'A', 0x41, 'x'},
		"truncated":              {0xa1, 0x61, 'A'},
		"trailing":               {0xa0, 0},
		"wrong map order":        {0xa2, 0x62, 'B', 'B', 0x61, 'y', 0x61, 'A', 0x61, 'x'},
		"nonminimal text length": {0xa1, 0x78, 0x01, 'A', 0x61, 'x'},
		"empty key":              {0xa1, 0x60, 0x61, 'x'},
		"too many map pairs":     {0xb9, 0x10, 0x01},
		"oversized":              make([]byte, MaxPayloadBytes+1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Decode(data); err == nil {
				t.Fatal("accepted invalid payload")
			}
		})
	}
}

func TestSecretMapBoundsAndSemanticNames(t *testing.T) {
	t.Parallel()
	for name, secrets := range map[string]SecretMap{
		"empty key":          {"": "value"},
		"invalid key UTF8":   {string([]byte{0xff}): "value"},
		"invalid value UTF8": {"key": string([]byte{0xff})},
		"long key":           {strings.Repeat("x", MaxKeyBytes+1): "value"},
		"large value":        {"key": strings.Repeat("x", MaxPayloadBytes)},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Encode(secrets); !errors.Is(err, ErrInvalidSecretMap) {
				t.Fatalf("Encode = %v", err)
			}
		})
	}
	secrets := SecretMap{}
	for i := range MaxEntries {
		secrets[fmt.Sprintf("k%d", i)] = ""
	}
	data, err := Encode(secrets)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := Decode(data); err != nil || len(got) != MaxEntries {
		t.Fatalf("boundary decode = %d, %v", len(got), err)
	}
	secrets["extra"] = ""
	if _, err := Encode(secrets); !errors.Is(err, ErrInvalidSecretMap) {
		t.Fatal(err)
	}
	// Exporter constraints must not leak into the semantic payload model.
	data, err = Encode(SecretMap{"service/password": "secret\x00bytes"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Decode(data); err != nil {
		t.Fatal(err)
	}
	// Raw text fitting the limit can still exceed it after CBOR headers.
	if _, err := Encode(SecretMap{"A": strings.Repeat("v", MaxPayloadBytes-1)}); !errors.Is(err, ErrInvalidSecretMap) {
		t.Fatalf("encoded size bound: %v", err)
	}
}

type readerFunc func([]byte) (int, error)

func (f readerFunc) Read(p []byte) (int, error) { return f(p) }

type borrowedStream struct {
	io.Reader
	closed bool
}

func (s *borrowedStream) Close() error { s.closed = true; return nil }

func TestDotenvArtifactSemanticRoundTrip(t *testing.T) {
	t.Parallel()
	input := []byte("# comment\nexport API_KEY = 'abc'\nEMPTY=\nMULTI=\"line1\\nline2\"\nLITERAL='${API_KEY}'\nUNICODE='e\u0301'\n")
	want, err := ImportDotenv(input)
	if err != nil {
		t.Fatal(err)
	}
	metadata := artifact.Metadata{Name: "secrets", Annotations: map[string]string{
		"aws.example/endpoint": "https://untrusted.example",
		"enbu.net/path":        "../../do-not-write",
		"enbu.net/plugin":      "https://untrusted.example/plugin",
	}}
	a, payload, err := NewArtifact("11111111-1111-4111-8111-111111111111", metadata, want)
	if err != nil {
		t.Fatal(err)
	}
	if a.Schema != Schema() || len(a.Payloads) != 1 || a.Payloads[0].Size != uint64(len(payload)) || a.Payloads[0].Digest != digest.FromBytes(payload) {
		t.Fatal("incorrect artifact payload reference")
	}
	manifest, err := artifact.EncodeArtifact(a)
	if err != nil {
		t.Fatal(err)
	}
	a, err = artifact.DecodeArtifact(manifest)
	if err != nil {
		t.Fatal(err)
	}
	stream := &borrowedStream{Reader: bytes.NewReader(payload)}
	got, err := ReadArtifact(context.Background(), a, stream)
	if stream.closed {
		t.Fatal("closed borrowed plaintext stream")
	}
	if err != nil {
		t.Fatal(err)
	}
	exported, err := ExportDotenv(got)
	if err != nil {
		t.Fatal(err)
	}
	final, err := ImportDotenv(exported)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(final, want) {
		t.Fatalf("semantic round trip changed values: %#v", final)
	}
	if !reflect.DeepEqual(a.Metadata.Annotations, metadata.Annotations) {
		t.Fatal("metadata changed")
	}
}

func TestReadArtifactRejectsBeforeReading(t *testing.T) {
	t.Parallel()
	for name, mutate := range map[string]func(*artifact.Artifact){
		"schema":           func(a *artifact.Artifact) { a.Schema.Kind = "Opaque" },
		"payload missing":  func(a *artifact.Artifact) { a.Payloads = nil },
		"extra payload":    func(a *artifact.Artifact) { p := a.Payloads[0]; p.Name = "extra"; a.Payloads = append(a.Payloads, p) },
		"wrong name":       func(a *artifact.Artifact) { a.Payloads[0].Name = "other" },
		"wrong media":      func(a *artifact.Artifact) { a.Payloads[0].MediaType = "text/plain" },
		"too large":        func(a *artifact.Artifact) { a.Payloads[0].Size = MaxPayloadBytes + 1 },
		"invalid artifact": func(a *artifact.Artifact) { a.UID = "bad" },
	} {
		t.Run(name, func(t *testing.T) {
			a, _, err := NewArtifact("11111111-1111-4111-8111-111111111111", artifact.Metadata{Name: "secrets"}, SecretMap{})
			if err != nil {
				t.Fatal(err)
			}
			mutate(&a)
			_, err = ReadArtifact(context.Background(), a, readerFunc(func([]byte) (int, error) {
				t.Fatal("read rejected artifact")
				return 0, nil
			}))
			if err == nil {
				t.Fatal("accepted invalid artifact")
			}
			if name == "schema" && !errors.Is(err, ErrUnsupportedSchema) {
				t.Fatal(err)
			}
		})
	}
}

func TestReadArtifactRejectsCorruptedContent(t *testing.T) {
	t.Parallel()
	a, _, err := NewArtifact("11111111-1111-4111-8111-111111111111", artifact.Metadata{Name: "secrets"}, SecretMap{"A": "x"})
	if err != nil {
		t.Fatal(err)
	}
	data, err := Encode(SecretMap{"A": "y"})
	if err != nil {
		t.Fatal(err)
	}
	stream := &borrowedStream{Reader: bytes.NewReader(data)}
	_, err = ReadArtifact(context.Background(), a, stream)
	if stream.closed {
		t.Fatal("closed borrowed plaintext stream on failure")
	}
	if !errors.Is(err, content.ErrDigestMismatch) {
		t.Fatalf("read corrupted payload: %v", err)
	}
}

func TestNewArtifactRejectsInvalidMetadata(t *testing.T) {
	t.Parallel()
	if _, _, err := NewArtifact("bad", artifact.Metadata{Name: "secrets"}, SecretMap{}); !errors.Is(err, artifact.ErrInvalidArtifact) {
		t.Fatal(err)
	}
	if _, _, err := NewArtifact("11111111-1111-4111-8111-111111111111", artifact.Metadata{Name: "secrets"}, SecretMap{"": "value"}); !errors.Is(err, ErrInvalidSecretMap) {
		t.Fatal(err)
	}
}

func FuzzDecode(f *testing.F) {
	seed, err := Encode(SecretMap{"A": "x"})
	if err != nil {
		f.Fatal(err)
	}
	f.Add(seed)
	f.Add([]byte{0xa0})
	f.Add([]byte{0xff})
	f.Fuzz(func(t *testing.T, data []byte) {
		secrets, err := Decode(data)
		if err != nil {
			return
		}
		encoded, err := Encode(secrets)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(data, encoded) {
			t.Fatal("accepted noncanonical payload")
		}
	})
}

func TestRejectsNoncanonicalEncoderOutput(t *testing.T) {
	t.Parallel()
	mode, err := (cbor.EncOptions{Sort: cbor.SortNone}).EncMode()
	if err != nil {
		t.Fatal(err)
	}
	// A struct fixes key ordering rather than depending on random map iteration.
	data, err := mode.Marshal(struct {
		BB string `cbor:"BB"`
		A  string `cbor:"A"`
	}{"y", "x"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Decode(data); !errors.Is(err, ErrNonCanonicalEncoding) {
		t.Fatal(err)
	}
}
