package schema

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"hash"
	"io"
	"sort"
	"sync"

	"github.com/opencontainers/go-digest"
)

// FileTreeInput is a single-use file stream selected by the trusted host.
// The importer never owns or closes Reader and never buffers its contents.
type FileTreeInput struct {
	Path      string
	MediaType string
	Reader    io.Reader
}

// FileTreeNamedStream is directly adaptable to a schema-neutral sealing
// pipeline. File payload names are opaque and unrelated to logical paths. The
// final stream is always the canonical FileTree index and must be consumed
// after every preceding file stream reaches EOF.
type FileTreeNamedStream struct {
	Name      string
	MediaType string
	Reader    io.Reader
}

// FileTreeImport is a one-shot streaming import. It retains only hashes,
// counts, and bounded index metadata; file bodies remain in caller Readers.
type FileTreeImport struct {
	streams []FileTreeNamedStream
	index   *fileTreeIndexReader
}

// NewFileTreeImport validates and deterministically orders logical paths, then
// returns opaque single-use streams followed by a lazy canonical index stream.
// No input is read until a returned stream is consumed.
func NewFileTreeImport(ctx context.Context, inputs []FileTreeInput) (*FileTreeImport, error) {
	if ctx == nil {
		return nil, fmt.Errorf("%w: nil file-tree import context", ErrInvalidSchema)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(inputs) > MaxFileTreeEntries {
		return nil, fmt.Errorf("%w: file-tree exceeds %d inputs", ErrInvalidSchema, MaxFileTreeEntries)
	}

	ordered := append([]FileTreeInput(nil), inputs...)
	paths := make([]string, len(ordered))
	for inputIndex, input := range ordered {
		if input.Reader == nil {
			return nil, fmt.Errorf("%w: inputs[%d] has nil reader", ErrInvalidSchema, inputIndex)
		}
		paths[inputIndex] = input.Path
		canonicalMediaType, err := canonicalFileTreeMediaType(input.MediaType)
		if err != nil {
			return nil, fmt.Errorf("%w: inputs[%d] media type: %v", ErrInvalidSchema, inputIndex, err)
		}
		ordered[inputIndex].MediaType = canonicalMediaType
	}
	if err := ValidateFileTreePaths(paths); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidSchema, err)
	}
	sort.Slice(ordered, func(left, right int) bool {
		return ordered[left].Path < ordered[right].Path
	})

	states := make([]*fileTreeImportState, 0, len(ordered))
	streams := make([]FileTreeNamedStream, 0, len(ordered)+1)
	for inputIndex, input := range ordered {
		state := &fileTreeImportState{
			path:      input.Path,
			payload:   opaqueFileTreePayloadName(inputIndex),
			mediaType: input.MediaType,
			source:    input.Reader,
			hash:      sha256.New(),
			limit:     MaxFileTreeFileBytes,
		}
		states = append(states, state)
		streams = append(streams, FileTreeNamedStream{
			Name:      state.payload,
			MediaType: state.mediaType,
			Reader:    &fileTreePayloadReader{ctx: ctx, state: state},
		})
	}
	indexReader := &fileTreeIndexReader{ctx: ctx, files: states}
	streams = append(streams, FileTreeNamedStream{
		Name:      FileTreeIndexPayloadName,
		MediaType: FileTreeIndexMediaType,
		Reader:    indexReader,
	})
	return &FileTreeImport{streams: streams, index: indexReader}, nil
}

// Streams returns the ordered stream descriptors. Mutating the returned slice
// does not alter the import, but every Reader remains single-use.
func (result *FileTreeImport) Streams() []FileTreeNamedStream {
	if result == nil {
		return nil
	}
	streams := make([]FileTreeNamedStream, len(result.streams))
	copy(streams, result.streams)
	return streams
}

// Index becomes available only after every file stream reaches EOF. It is the
// same value encoded by the final stream.
func (result *FileTreeImport) Index() (FileTreeIndex, error) {
	if result == nil || result.index == nil {
		return FileTreeIndex{}, fmt.Errorf("%w: nil file-tree import", ErrInvalidSchema)
	}
	return result.index.indexValue()
}

type fileTreeImportState struct {
	mu sync.Mutex

	path      string
	payload   string
	mediaType string
	source    io.Reader
	hash      hash.Hash
	limit     int64
	size      int64
	digest    digest.Digest
	finished  bool
	failure   error
}

type fileTreePayloadReader struct {
	ctx   context.Context
	state *fileTreeImportState
}

func (reader *fileTreePayloadReader) Read(buffer []byte) (int, error) {
	if reader == nil || reader.state == nil || reader.ctx == nil {
		return 0, fmt.Errorf("%w: invalid file-tree stream", ErrInvalidSchema)
	}
	state := reader.state
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.failure != nil {
		return 0, state.failure
	}
	if state.finished {
		return 0, io.EOF
	}
	if err := reader.ctx.Err(); err != nil {
		state.failure = err
		return 0, err
	}
	if len(buffer) == 0 {
		return 0, nil
	}

	read, readErr := state.source.Read(buffer)
	if read < 0 || read > len(buffer) {
		state.failure = fmt.Errorf("%w: invalid Reader result", ErrInvalidSchema)
		return 0, state.failure
	}
	if read > 0 {
		if int64(read) > state.limit-state.size {
			state.failure = fmt.Errorf("%w: file %q exceeds %d bytes", ErrInvalidSchema, state.path, state.limit)
			return read, state.failure
		}
		if _, err := state.hash.Write(buffer[:read]); err != nil {
			state.failure = fmt.Errorf("%w: hash file %q: %v", ErrInvalidSchema, state.path, err)
			return read, state.failure
		}
		state.size += int64(read)
	}

	switch {
	case errors.Is(readErr, io.EOF):
		state.digest = digest.NewDigest(digest.SHA256, state.hash)
		state.finished = true
		return read, io.EOF
	case readErr != nil:
		state.failure = readErr
		return read, readErr
	default:
		return read, nil
	}
}

func (state *fileTreeImportState) entry() (FileTreeEntry, error) {
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.failure != nil {
		return FileTreeEntry{}, state.failure
	}
	if !state.finished {
		return FileTreeEntry{}, ErrFileTreeStreamsIncomplete
	}
	return FileTreeEntry{
		Path:      state.path,
		Payload:   state.payload,
		Digest:    state.digest,
		Size:      state.size,
		MediaType: state.mediaType,
	}, nil
}

type fileTreeIndexReader struct {
	mu sync.Mutex

	ctx     context.Context
	files   []*fileTreeImportState
	built   bool
	index   FileTreeIndex
	encoded []byte
	reader  *bytes.Reader
	failure error
}

func (reader *fileTreeIndexReader) Read(buffer []byte) (int, error) {
	if reader == nil {
		return 0, fmt.Errorf("%w: nil file-tree index stream", ErrInvalidSchema)
	}
	reader.mu.Lock()
	defer reader.mu.Unlock()
	if err := reader.buildLocked(); err != nil {
		return 0, err
	}
	if err := reader.ctx.Err(); err != nil {
		return 0, err
	}
	return reader.reader.Read(buffer)
}

func (reader *fileTreeIndexReader) indexValue() (FileTreeIndex, error) {
	reader.mu.Lock()
	defer reader.mu.Unlock()
	if err := reader.buildLocked(); err != nil {
		return FileTreeIndex{}, err
	}
	return cloneFileTreeIndex(reader.index), nil
}

func (reader *fileTreeIndexReader) buildLocked() error {
	if reader.failure != nil {
		return reader.failure
	}
	if reader.built {
		return nil
	}
	if reader.ctx == nil {
		reader.failure = fmt.Errorf("%w: nil file-tree index context", ErrInvalidSchema)
		return reader.failure
	}
	if err := reader.ctx.Err(); err != nil {
		reader.failure = err
		return err
	}
	index := FileTreeIndex{
		APIVersion: FileTreeIndexAPIVersion,
		Kind:       FileTreeIndexKind,
		Entries:    make([]FileTreeEntry, 0, len(reader.files)),
	}
	for _, state := range reader.files {
		entry, err := state.entry()
		if err != nil {
			return err
		}
		index.Entries = append(index.Entries, entry)
	}
	encoded, err := EncodeFileTreeIndex(index)
	if err != nil {
		reader.failure = err
		return err
	}
	reader.index = index
	reader.encoded = encoded
	reader.reader = bytes.NewReader(reader.encoded)
	reader.built = true
	return nil
}

func opaqueFileTreePayloadName(index int) string {
	return fmt.Sprintf("file-%04d", index+1)
}
