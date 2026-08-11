package schema

import (
	"bytes"
	"errors"
	"fmt"
	"mime"
	"sort"

	"github.com/enbu-net/enbu/pkg/artifact"
	"github.com/opencontainers/go-digest"
)

const (
	FileTreeIndexAPIVersion  = "schemas.enbu.net/v1alpha1"
	FileTreeIndexKind        = "FileTreeIndex"
	FileTreeIndexPayloadName = "filetree-index"
	FileTreeIndexMediaType   = "application/vnd.enbu.schema.file-tree-index.v1+cbor"

	MaxFileTreeEntries              = artifact.MaxPayloads - 1
	MaxFileTreePathBytes            = 4 * 1024
	MaxFileTreeSegmentBytes         = 255
	MaxFileTreeDepth                = 64
	MaxFileTreeMediaTypeBytes       = 255
	MaxFileTreeIndexBytes           = 8 * 1024 * 1024
	MaxFileTreeFileBytes      int64 = MaxOpaqueBytes
)

var (
	ErrFileTreeStreamsIncomplete = errors.New("schema: file-tree streams incomplete")
	ErrFileTreePathNotFound      = errors.New("schema: file-tree path not found")
)

// FileTreeEntry maps a portable logical path to an opaque Resource payload.
// Path never doubles as a PayloadRef name, and no native filesystem metadata
// is represented here.
type FileTreeEntry struct {
	Path      string        `cbor:"path" json:"path"`
	Payload   string        `cbor:"payload" json:"payload"`
	Digest    digest.Digest `cbor:"digest" json:"digest"`
	Size      int64         `cbor:"size" json:"size"`
	MediaType string        `cbor:"mediaType" json:"mediaType"`
}

func (entry FileTreeEntry) Validate() error {
	if err := ValidateFileTreePath(entry.Path); err != nil {
		return fmt.Errorf("%w: entry path %q: %w", ErrInvalidSchema, entry.Path, err)
	}
	if entry.Payload == FileTreeIndexPayloadName {
		return fmt.Errorf("%w: entry %q uses reserved index payload", ErrInvalidSchema, entry.Path)
	}
	if entry.Size > MaxFileTreeFileBytes {
		return fmt.Errorf("%w: entry %q exceeds file size bound", ErrInvalidSchema, entry.Path)
	}
	canonicalMediaType, err := canonicalFileTreeMediaType(entry.MediaType)
	if err != nil || canonicalMediaType != entry.MediaType {
		return fmt.Errorf("%w: entry %q has non-canonical media type", ErrInvalidSchema, entry.Path)
	}
	if err := (artifact.PayloadRef{
		Name:      entry.Payload,
		MediaType: entry.MediaType,
		Digest:    entry.Digest,
		Size:      entry.Size,
	}).Validate(); err != nil {
		return fmt.Errorf("%w: entry %q payload: %v", ErrInvalidSchema, entry.Path, err)
	}
	return nil
}

// FileTreeIndex is the canonical schema payload. Entries are encoded in Path
// order; callers may provide any order to EncodeFileTreeIndex, which sorts a
// copy without mutating the input.
type FileTreeIndex struct {
	APIVersion string          `cbor:"apiVersion" json:"apiVersion"`
	Kind       string          `cbor:"kind" json:"kind"`
	Entries    []FileTreeEntry `cbor:"entries" json:"entries"`
}

func (index FileTreeIndex) Validate() error {
	if index.APIVersion != FileTreeIndexAPIVersion || index.Kind != FileTreeIndexKind {
		return fmt.Errorf("%w: file-tree index envelope", ErrInvalidSchema)
	}
	if len(index.Entries) > MaxFileTreeEntries {
		return fmt.Errorf("%w: file-tree exceeds %d entries", ErrInvalidSchema, MaxFileTreeEntries)
	}

	paths := make([]string, 0, len(index.Entries))
	payloads := make(map[string]struct{}, len(index.Entries))
	canonicalEntries := append([]FileTreeEntry(nil), index.Entries...)
	sort.Slice(canonicalEntries, func(left, right int) bool {
		return canonicalEntries[left].Path < canonicalEntries[right].Path
	})
	var totalSize int64
	for entryIndex, entry := range index.Entries {
		if err := entry.Validate(); err != nil {
			return fmt.Errorf("%w: entries[%d]: %v", ErrInvalidSchema, entryIndex, err)
		}
		if _, exists := payloads[entry.Payload]; exists {
			return fmt.Errorf("%w: duplicate payload %q", ErrInvalidSchema, entry.Payload)
		}
		payloads[entry.Payload] = struct{}{}
		paths = append(paths, entry.Path)
		if totalSize > int64(MaxFileTreeEntries)*MaxFileTreeFileBytes-entry.Size {
			return fmt.Errorf("%w: file-tree total size overflow", ErrInvalidSchema)
		}
		totalSize += entry.Size
	}
	for entryIndex, entry := range canonicalEntries {
		if entry.Payload != opaqueFileTreePayloadName(entryIndex) {
			return fmt.Errorf("%w: path %q must use opaque payload %q", ErrInvalidSchema, entry.Path, opaqueFileTreePayloadName(entryIndex))
		}
	}
	if err := ValidateFileTreePaths(paths); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidSchema, err)
	}
	return nil
}

// EncodeFileTreeIndex emits the sole deterministic CBOR representation.
func EncodeFileTreeIndex(index FileTreeIndex) ([]byte, error) {
	if err := index.Validate(); err != nil {
		return nil, err
	}
	canonical := cloneFileTreeIndex(index)
	sort.Slice(canonical.Entries, func(left, right int) bool {
		return canonical.Entries[left].Path < canonical.Entries[right].Path
	})
	encoded, err := artifact.MarshalCanonical(canonical)
	if err != nil {
		return nil, fmt.Errorf("%w: encode file-tree index: %v", ErrInvalidSchema, err)
	}
	if len(encoded) > MaxFileTreeIndexBytes {
		return nil, fmt.Errorf("%w: file-tree index exceeds %d encoded bytes", ErrInvalidSchema, MaxFileTreeIndexBytes)
	}
	return encoded, nil
}

// DecodeFileTreeIndex rejects unknown fields and every representation that is
// not byte-for-byte identical to EncodeFileTreeIndex output.
func DecodeFileTreeIndex(encoded []byte) (FileTreeIndex, error) {
	if len(encoded) == 0 || len(encoded) > MaxFileTreeIndexBytes {
		return FileTreeIndex{}, fmt.Errorf("%w: file-tree index encoded size", ErrInvalidSchema)
	}
	var index FileTreeIndex
	if err := artifact.UnmarshalStrict(encoded, &index); err != nil {
		return FileTreeIndex{}, fmt.Errorf("%w: decode file-tree index: %v", ErrInvalidSchema, err)
	}
	canonical, err := EncodeFileTreeIndex(index)
	if err != nil {
		return FileTreeIndex{}, err
	}
	if !bytes.Equal(encoded, canonical) {
		return FileTreeIndex{}, fmt.Errorf("%w: %w", ErrInvalidSchema, artifact.ErrNonCanonicalEncoding)
	}
	return index, nil
}

// FileTreeMappedFile is a validated materialization target and its exact
// Resource payload reference.
type FileTreeMappedFile struct {
	Path    string
	Payload artifact.PayloadRef
}

// FileTreeMapping is immutable after construction. It proves that the
// canonical index and Resource PayloadRefs are a one-to-one, digest/size/media
// type consistent mapping with no unreferenced payloads.
type FileTreeMapping struct {
	files  []FileTreeMappedFile
	byPath map[string]int
}

// NewFileTreeMapping validates an already decoded index against the complete
// PayloadRef set of its FileTree Resource, including the index payload itself.
func NewFileTreeMapping(index FileTreeIndex, payloads []artifact.PayloadRef) (FileTreeMapping, error) {
	encoded, err := EncodeFileTreeIndex(index)
	if err != nil {
		return FileTreeMapping{}, err
	}
	if len(payloads) != len(index.Entries)+1 {
		return FileTreeMapping{}, fmt.Errorf("%w: file-tree payload count mismatch", ErrInvalidSchema)
	}

	byName := make(map[string]artifact.PayloadRef, len(payloads))
	for payloadIndex, payload := range payloads {
		if err := payload.Validate(); err != nil {
			return FileTreeMapping{}, fmt.Errorf("%w: payloads[%d]: %v", ErrInvalidSchema, payloadIndex, err)
		}
		canonicalMediaType, mediaErr := canonicalFileTreeMediaType(payload.MediaType)
		if mediaErr != nil || canonicalMediaType != payload.MediaType {
			return FileTreeMapping{}, fmt.Errorf("%w: payload %q has non-canonical media type", ErrInvalidSchema, payload.Name)
		}
		if _, exists := byName[payload.Name]; exists {
			return FileTreeMapping{}, fmt.Errorf("%w: duplicate Resource payload %q", ErrInvalidSchema, payload.Name)
		}
		byName[payload.Name] = payload
	}

	wantIndexPayload := artifact.PayloadRef{
		Name:      FileTreeIndexPayloadName,
		MediaType: FileTreeIndexMediaType,
		Digest:    digest.FromBytes(encoded),
		Size:      int64(len(encoded)),
	}
	indexPayload, exists := byName[FileTreeIndexPayloadName]
	if !exists || indexPayload != wantIndexPayload {
		return FileTreeMapping{}, fmt.Errorf("%w: index payload digest/size/media mismatch", ErrInvalidSchema)
	}

	canonical := cloneFileTreeIndex(index)
	sort.Slice(canonical.Entries, func(left, right int) bool {
		return canonical.Entries[left].Path < canonical.Entries[right].Path
	})
	mapping := FileTreeMapping{
		files:  make([]FileTreeMappedFile, 0, len(canonical.Entries)),
		byPath: make(map[string]int, len(canonical.Entries)),
	}
	referenced := map[string]struct{}{FileTreeIndexPayloadName: {}}
	for _, entry := range canonical.Entries {
		payload, exists := byName[entry.Payload]
		if !exists || payload.Digest != entry.Digest || payload.Size != entry.Size || payload.MediaType != entry.MediaType {
			return FileTreeMapping{}, fmt.Errorf("%w: payload %q digest/size/media mismatch", ErrInvalidSchema, entry.Payload)
		}
		if _, exists := referenced[entry.Payload]; exists {
			return FileTreeMapping{}, fmt.Errorf("%w: payload %q referenced more than once", ErrInvalidSchema, entry.Payload)
		}
		referenced[entry.Payload] = struct{}{}
		mapping.byPath[entry.Path] = len(mapping.files)
		mapping.files = append(mapping.files, FileTreeMappedFile{Path: entry.Path, Payload: payload})
	}
	if len(referenced) != len(byName) {
		return FileTreeMapping{}, fmt.Errorf("%w: unreferenced Resource payload", ErrInvalidSchema)
	}
	return mapping, nil
}

// DecodeFileTreeMapping is the materializer entry point: it first enforces
// strict canonical CBOR, then proves the mapping against the opened Revision.
func DecodeFileTreeMapping(encoded []byte, payloads []artifact.PayloadRef) (FileTreeMapping, error) {
	index, err := DecodeFileTreeIndex(encoded)
	if err != nil {
		return FileTreeMapping{}, err
	}
	return NewFileTreeMapping(index, payloads)
}

func (mapping FileTreeMapping) Files() []FileTreeMappedFile {
	files := make([]FileTreeMappedFile, len(mapping.files))
	copy(files, mapping.files)
	return files
}

func (mapping FileTreeMapping) Resolve(logicalPath string) (artifact.PayloadRef, error) {
	if err := ValidateFileTreePath(logicalPath); err != nil {
		return artifact.PayloadRef{}, err
	}
	index, exists := mapping.byPath[logicalPath]
	if !exists || index < 0 || index >= len(mapping.files) {
		return artifact.PayloadRef{}, ErrFileTreePathNotFound
	}
	return mapping.files[index].Payload, nil
}

func cloneFileTreeIndex(index FileTreeIndex) FileTreeIndex {
	clone := index
	clone.Entries = append([]FileTreeEntry(nil), index.Entries...)
	return clone
}

func canonicalFileTreeMediaType(value string) (string, error) {
	if value == "" || len(value) > MaxFileTreeMediaTypeBytes {
		return "", errors.New("media type size")
	}
	mediaType, parameters, err := mime.ParseMediaType(value)
	if err != nil {
		return "", err
	}
	canonical := mime.FormatMediaType(mediaType, parameters)
	if canonical == "" || len(canonical) > MaxFileTreeMediaTypeBytes {
		return "", errors.New("media type cannot be canonicalized")
	}
	return canonical, nil
}
