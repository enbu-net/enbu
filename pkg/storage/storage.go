// Package storage stores immutable encrypted blobs and small mutable refs.
// Blobs are addressed by the SHA-256 digest of their stored (encrypted) bytes,
// never of plaintext. Refs name the blob currently in use and are updated with
// compare-and-swap. Versions are backend-specific concurrency tokens.
package storage

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/opencontainers/go-digest"
)

const MaxPayloadBytes = 10 * 1024 * 1024

var (
	ErrNotFound       = errors.New("storage object not found")
	ErrConflict       = errors.New("storage object changed")
	ErrTooLarge       = fmt.Errorf("payload exceeds %d bytes", MaxPayloadBytes)
	ErrEmptyBlob      = errors.New("blob is empty") // some registries reject zero-length blobs
	ErrDigestMismatch = errors.New("storage blob digest mismatch")
)

type Version string

// Blobs stores immutable content. Storing existing content succeeds.
type Blobs interface {
	// Put streams r into the store and returns the SHA-256 digest of its bytes.
	Put(context.Context, io.Reader) (digest.Digest, error)
	// Open returns a reader that fails at EOF if the bytes do not match the digest.
	Open(context.Context, digest.Digest) (io.ReadCloser, error)
}

// Refs maps names to blob digests.
type Refs interface {
	Get(context.Context, string) (digest.Digest, Version, error)
	// An empty expected version means create only. Otherwise replace exactly
	// the version read by Get. OCI can only check before writing.
	Put(context.Context, string, digest.Digest, Version) error
	List(context.Context, string) ([]string, error)
}

// LegacyDetector is implemented by Refs backends that can recognise data
// written in the pre-blob layout, which the current layout cannot read.
type LegacyDetector interface {
	HasLegacy(context.Context) (bool, error)
}

type Store struct {
	Blobs Blobs
	Refs  Refs
}

func ValidateKey(key string) error {
	if key == "" || len(key) > 128 || key == "." || key == ".." {
		return fmt.Errorf("invalid storage key %q", key)
	}
	for _, r := range key {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' || r == '.' {
			continue
		}
		return fmt.Errorf("invalid storage key %q", key)
	}
	return nil
}

func ValidateDigest(d digest.Digest) error {
	// Validate first: Algorithm panics on a digest without a separator.
	if err := d.Validate(); err != nil {
		return err
	}
	if d.Algorithm() != digest.SHA256 {
		return fmt.Errorf("unsupported digest %q", d)
	}
	return nil
}

type ctxReader struct {
	ctx context.Context
	r   io.Reader
}

func (c ctxReader) Read(p []byte) (int, error) {
	if err := c.ctx.Err(); err != nil {
		return 0, err
	}
	return c.r.Read(p)
}

// copyHashed copies 1 to MaxPayloadBytes bytes from r to dst and returns the digest and size.
func copyHashed(ctx context.Context, dst io.Writer, r io.Reader) (digest.Digest, int64, error) {
	h := digest.SHA256.Digester()
	n, err := io.Copy(io.MultiWriter(dst, h.Hash()), io.LimitReader(ctxReader{ctx, r}, MaxPayloadBytes+1))
	if err != nil {
		return "", 0, err
	}
	if n > MaxPayloadBytes {
		return "", 0, ErrTooLarge
	}
	if n == 0 {
		return "", 0, ErrEmptyBlob
	}
	return h.Digest(), n, nil
}

// spooled is a blob staged in a temporary file, so its digest and size are known
// before an upload starts.
type spooled struct {
	*os.File
	Digest digest.Digest
	Size   int64
}

func spool(ctx context.Context, r io.Reader) (*spooled, error) {
	f, err := os.CreateTemp("", "enbu-blob-")
	if err != nil {
		return nil, err
	}
	s := &spooled{File: f}
	d, n, err := copyHashed(ctx, f, r)
	if err == nil {
		_, err = f.Seek(0, io.SeekStart)
	}
	if err != nil {
		_ = s.Close()
		return nil, err
	}
	s.Digest, s.Size = d, n
	return s, nil
}

// Close closes and removes the temporary file.
func (s *spooled) Close() error {
	err := s.File.Close()
	_ = os.Remove(s.Name())
	return err
}

// verifyReader fails at EOF unless the bytes read match the digest. It also
// refuses content larger than MaxPayloadBytes.
type verifyReader struct {
	rc  io.ReadCloser
	v   digest.Verifier
	n   int64
	err error
}

func newVerifyReader(rc io.ReadCloser, d digest.Digest) io.ReadCloser {
	return &verifyReader{rc: rc, v: d.Verifier()}
}

func (r *verifyReader) Read(p []byte) (int, error) {
	if r.err != nil {
		return 0, r.err
	}
	n, err := r.rc.Read(p)
	r.n += int64(n)
	if r.n > MaxPayloadBytes {
		r.err = ErrTooLarge
		return 0, r.err
	}
	_, _ = r.v.Write(p[:n])
	if errors.Is(err, io.EOF) && !r.v.Verified() {
		r.err = ErrDigestMismatch
		return n, r.err
	}
	return n, err
}

func (r *verifyReader) Close() error { return r.rc.Close() }

func parseRef(b []byte) (digest.Digest, error) {
	d := digest.Digest(b)
	if err := ValidateDigest(d); err != nil {
		return "", fmt.Errorf("invalid ref target: %w", err)
	}
	return d, nil
}
