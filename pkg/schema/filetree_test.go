package schema

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"

	"github.com/enbu-net/enbu/pkg/artifact"
	"github.com/opencontainers/go-digest"
)

func TestFileTreeIndexCanonicalCBORRoundTrip(t *testing.T) {
	t.Parallel()

	first := testFileTreeEntry("a/config.txt", "file-0001", "alpha", "text/plain")
	second := testFileTreeEntry("z/data.bin", "file-0002", "bravo", "application/octet-stream")
	index := FileTreeIndex{
		APIVersion: FileTreeIndexAPIVersion,
		Kind:       FileTreeIndexKind,
		Entries:    []FileTreeEntry{second, first},
	}
	encoded, err := EncodeFileTreeIndex(index)
	if err != nil {
		t.Fatalf("EncodeFileTreeIndex: %v", err)
	}
	if index.Entries[0].Path != second.Path {
		t.Fatal("EncodeFileTreeIndex mutated caller order")
	}
	decoded, err := DecodeFileTreeIndex(encoded)
	if err != nil {
		t.Fatalf("DecodeFileTreeIndex: %v", err)
	}
	if len(decoded.Entries) != 2 || decoded.Entries[0] != first || decoded.Entries[1] != second {
		t.Fatalf("decoded entries = %#v", decoded.Entries)
	}

	nonCanonical, err := artifact.MarshalCanonical(index)
	if err != nil {
		t.Fatalf("MarshalCanonical(non-canonical order): %v", err)
	}
	if _, err := DecodeFileTreeIndex(nonCanonical); !errors.Is(err, artifact.ErrNonCanonicalEncoding) {
		t.Fatalf("DecodeFileTreeIndex(non-canonical order) = %v", err)
	}
}

func TestFileTreeIndexRejectsUnknownFields(t *testing.T) {
	t.Parallel()

	wire := struct {
		APIVersion string          `cbor:"apiVersion"`
		Kind       string          `cbor:"kind"`
		Entries    []FileTreeEntry `cbor:"entries"`
		SecretPath string          `cbor:"secretPath"`
	}{
		APIVersion: FileTreeIndexAPIVersion,
		Kind:       FileTreeIndexKind,
		Entries:    []FileTreeEntry{},
		SecretPath: "/private/input",
	}
	encoded, err := artifact.MarshalCanonical(wire)
	if err != nil {
		t.Fatalf("MarshalCanonical: %v", err)
	}
	if _, err := DecodeFileTreeIndex(encoded); !errors.Is(err, ErrInvalidSchema) {
		t.Fatalf("DecodeFileTreeIndex(unknown field) = %v", err)
	}
}

func TestFileTreeIndexRejectsPathPayloadAndBoundsViolations(t *testing.T) {
	t.Parallel()

	valid := testFileTreeEntry("config/app.env", "file-0001", "value", "text/plain")
	tests := []struct {
		name    string
		entries []FileTreeEntry
	}{
		{name: "exact path duplicate", entries: []FileTreeEntry{valid, withFileTreePath(valid, "config/app.env", "file-0002")}},
		{name: "case collision", entries: []FileTreeEntry{valid, withFileTreePath(valid, "CONFIG/APP.ENV", "file-0002")}},
		{name: "unicode case fold collision", entries: []FileTreeEntry{
			withFileTreePath(valid, "Straße/key", "file-0001"),
			withFileTreePath(valid, "STRASSE/key", "file-0002"),
		}},
		{name: "file directory collision", entries: []FileTreeEntry{
			withFileTreePath(valid, "config", "file-0001"),
			withFileTreePath(valid, "config/app.env", "file-0002"),
		}},
		{name: "duplicate opaque payload", entries: []FileTreeEntry{
			valid,
			withFileTreePath(valid, "other.env", valid.Payload),
		}},
		{name: "reserved index payload", entries: []FileTreeEntry{
			withFileTreePath(valid, valid.Path, FileTreeIndexPayloadName),
		}},
		{name: "path revealing payload", entries: []FileTreeEntry{
			withFileTreePath(valid, valid.Path, "app.env"),
		}},
		{name: "oversized file", entries: []FileTreeEntry{
			func() FileTreeEntry {
				entry := valid
				entry.Size = MaxFileTreeFileBytes + 1
				return entry
			}(),
		}},
		{name: "non canonical media type", entries: []FileTreeEntry{
			func() FileTreeEntry {
				entry := valid
				entry.MediaType = "TEXT/PLAIN"
				return entry
			}(),
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			index := FileTreeIndex{APIVersion: FileTreeIndexAPIVersion, Kind: FileTreeIndexKind, Entries: test.entries}
			if _, err := EncodeFileTreeIndex(index); !errors.Is(err, ErrInvalidSchema) {
				t.Fatalf("EncodeFileTreeIndex = %v", err)
			}
		})
	}

	tooMany := make([]FileTreeEntry, MaxFileTreeEntries+1)
	index := FileTreeIndex{APIVersion: FileTreeIndexAPIVersion, Kind: FileTreeIndexKind, Entries: tooMany}
	if _, err := EncodeFileTreeIndex(index); !errors.Is(err, ErrInvalidSchema) {
		t.Fatalf("EncodeFileTreeIndex(too many) = %v", err)
	}
	if _, err := DecodeFileTreeIndex(make([]byte, MaxFileTreeIndexBytes+1)); !errors.Is(err, ErrInvalidSchema) {
		t.Fatalf("DecodeFileTreeIndex(oversized encoding) = %v", err)
	}
}

func TestFileTreePortablePathGrammarRejectsAllPlatformHazards(t *testing.T) {
	t.Parallel()

	tooDeep := strings.Repeat("a/", MaxFileTreeDepth) + "z"
	invalid := []string{
		"/absolute", `C:\secret`, `\\server\share`, `a\b`, "a:b", "a/../b",
		"a/CON.txt", "a/trailing.", "a/trailing ", `a/quote"`, "a/control\n",
		"cafe\u0301/key", strings.Repeat("x", MaxFileTreeSegmentBytes+1), tooDeep,
	}
	for _, logicalPath := range invalid {
		if err := ValidateFileTreePath(logicalPath); !errors.Is(err, ErrInvalidPath) {
			t.Errorf("ValidateFileTreePath(%q) = %v", logicalPath, err)
		}
	}
	if err := ValidateFileTreePath("café/nested/config.json"); err != nil {
		t.Fatalf("ValidateFileTreePath(valid NFC path): %v", err)
	}
}

func TestFileTreeMappingChecksEveryPayloadFieldAndOffersValidatedResolution(t *testing.T) {
	t.Parallel()

	sharedDigest := digest.FromString("identical contents are valid independent files")
	index := FileTreeIndex{
		APIVersion: FileTreeIndexAPIVersion,
		Kind:       FileTreeIndexKind,
		Entries: []FileTreeEntry{
			{Path: "a.txt", Payload: "file-0001", Digest: sharedDigest, Size: 12, MediaType: "text/plain"},
			{Path: "nested/b.txt", Payload: "file-0002", Digest: sharedDigest, Size: 12, MediaType: "text/plain"},
		},
	}
	encoded, err := EncodeFileTreeIndex(index)
	if err != nil {
		t.Fatalf("EncodeFileTreeIndex: %v", err)
	}
	payloads := []artifact.PayloadRef{
		{Name: "file-0002", Digest: sharedDigest, Size: 12, MediaType: "text/plain"},
		{Name: FileTreeIndexPayloadName, Digest: digest.FromBytes(encoded), Size: int64(len(encoded)), MediaType: FileTreeIndexMediaType},
		{Name: "file-0001", Digest: sharedDigest, Size: 12, MediaType: "text/plain"},
	}
	mapping, err := DecodeFileTreeMapping(encoded, payloads)
	if err != nil {
		t.Fatalf("DecodeFileTreeMapping: %v", err)
	}
	files := mapping.Files()
	if len(files) != 2 || files[0].Path != "a.txt" || files[1].Path != "nested/b.txt" {
		t.Fatalf("Files = %#v", files)
	}
	resolved, err := mapping.Resolve("nested/b.txt")
	if err != nil || resolved.Name != "file-0002" {
		t.Fatalf("Resolve = %#v, %v", resolved, err)
	}
	if _, err := mapping.Resolve("missing.txt"); !errors.Is(err, ErrFileTreePathNotFound) {
		t.Fatalf("Resolve(missing) = %v", err)
	}
	files[0].Path = "mutated"
	if fresh := mapping.Files(); fresh[0].Path != "a.txt" {
		t.Fatal("Files exposed mutable mapping state")
	}

	mutations := []struct {
		name   string
		mutate func([]artifact.PayloadRef)
	}{
		{name: "duplicate payload", mutate: func(values []artifact.PayloadRef) { values[2].Name = values[0].Name }},
		{name: "file digest", mutate: func(values []artifact.PayloadRef) { values[0].Digest = digest.FromString("other") }},
		{name: "file size", mutate: func(values []artifact.PayloadRef) { values[0].Size++ }},
		{name: "file media type", mutate: func(values []artifact.PayloadRef) { values[0].MediaType = "application/octet-stream" }},
		{name: "index digest", mutate: func(values []artifact.PayloadRef) { values[1].Digest = digest.FromString("other-index") }},
		{name: "index size", mutate: func(values []artifact.PayloadRef) { values[1].Size++ }},
	}
	for _, mutation := range mutations {
		t.Run(mutation.name, func(t *testing.T) {
			modified := append([]artifact.PayloadRef(nil), payloads...)
			mutation.mutate(modified)
			if _, err := DecodeFileTreeMapping(encoded, modified); !errors.Is(err, ErrInvalidSchema) {
				t.Fatalf("DecodeFileTreeMapping = %v", err)
			}
		})
	}
}

func TestFileTreeImporterIsLazyStreamingAndKeepsPathsOutOfPayloadNames(t *testing.T) {
	t.Parallel()

	first := &observedReader{reader: strings.NewReader("alpha")}
	second := &observedReader{reader: strings.NewReader("bravo-charlie")}
	result, err := NewFileTreeImport(context.Background(), []FileTreeInput{
		{Path: "nested/private.env", MediaType: "TEXT/PLAIN", Reader: second},
		{Path: "config.json", MediaType: "application/json", Reader: first},
	})
	if err != nil {
		t.Fatalf("NewFileTreeImport: %v", err)
	}
	if first.reads != 0 || second.reads != 0 {
		t.Fatal("NewFileTreeImport eagerly read a file body")
	}
	streams := result.Streams()
	if len(streams) != 3 {
		t.Fatalf("stream count = %d, want 3", len(streams))
	}
	if streams[0].Name != "file-0001" || streams[1].Name != "file-0002" || streams[2].Name != FileTreeIndexPayloadName {
		t.Fatalf("opaque stream names = %#v", streams)
	}
	for _, stream := range streams {
		if strings.Contains(stream.Name, "/") || strings.Contains(stream.Name, "config") || strings.Contains(stream.Name, "private") {
			t.Fatalf("logical path leaked into payload name %q", stream.Name)
		}
	}
	if _, err := result.Index(); !errors.Is(err, ErrFileTreeStreamsIncomplete) {
		t.Fatalf("Index before stream EOF = %v", err)
	}

	for _, stream := range streams[:2] {
		if _, err := io.Copy(io.Discard, stream.Reader); err != nil {
			t.Fatalf("consume %q: %v", stream.Name, err)
		}
	}
	index, err := result.Index()
	if err != nil {
		t.Fatalf("Index: %v", err)
	}
	var indexBuffer bytes.Buffer
	if _, err := io.Copy(&indexBuffer, streams[2].Reader); err != nil {
		t.Fatalf("consume index stream: %v", err)
	}
	decoded, err := DecodeFileTreeIndex(indexBuffer.Bytes())
	if err != nil {
		t.Fatalf("DecodeFileTreeIndex(import output): %v", err)
	}
	if !reflect.DeepEqual(decoded, index) {
		t.Fatalf("streamed index = %#v, Index = %#v", decoded, index)
	}
	if len(index.Entries) != 2 || index.Entries[0].Path != "config.json" || index.Entries[1].Path != "nested/private.env" {
		t.Fatalf("index entries = %#v", index.Entries)
	}
	if index.Entries[0].Digest != digest.FromString("alpha") || index.Entries[1].Digest != digest.FromString("bravo-charlie") {
		t.Fatalf("stream digests = %#v", index.Entries)
	}
	if index.Entries[1].MediaType != "text/plain" {
		t.Fatalf("canonical media type = %q", index.Entries[1].MediaType)
	}
}

func TestFileTreeImporterPropagatesCancellationAndSizeBounds(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	result, err := NewFileTreeImport(ctx, []FileTreeInput{{Path: "secret", MediaType: "text/plain", Reader: strings.NewReader("value")}})
	if err != nil {
		t.Fatalf("NewFileTreeImport: %v", err)
	}
	cancel()
	buffer := make([]byte, 8)
	if _, err := result.Streams()[0].Reader.Read(buffer); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled stream Read = %v", err)
	}

	state := &fileTreeImportState{
		path: "bounded", payload: "file-0001", mediaType: "text/plain",
		source: strings.NewReader("four"), hash: sha256.New(), limit: 3,
	}
	reader := &fileTreePayloadReader{ctx: context.Background(), state: state}
	if read, err := reader.Read(make([]byte, 4)); read != 4 || !errors.Is(err, ErrInvalidSchema) {
		t.Fatalf("oversized stream Read = %d, %v", read, err)
	}
}

type observedReader struct {
	reader io.Reader
	reads  int
}

func (reader *observedReader) Read(buffer []byte) (int, error) {
	reader.reads++
	return reader.reader.Read(buffer)
}

func testFileTreeEntry(path, payload, contents, mediaType string) FileTreeEntry {
	return FileTreeEntry{
		Path:      path,
		Payload:   payload,
		Digest:    digest.FromString(contents),
		Size:      int64(len(contents)),
		MediaType: mediaType,
	}
}

func withFileTreePath(entry FileTreeEntry, path, payload string) FileTreeEntry {
	entry.Path = path
	entry.Payload = payload
	return entry
}
