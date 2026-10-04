package content

import (
	"bytes"
	"context"
	"errors"
	"io"
	"math"
	"testing"

	"github.com/enbu-net/enbu/pkg/artifact"
	"github.com/opencontainers/go-digest"
)

type sourceFunc func(context.Context, digest.Digest) (io.ReadCloser, error)

func (f sourceFunc) Open(ctx context.Context, d digest.Digest) (io.ReadCloser, error) {
	return f(ctx, d)
}

type trackedStream struct {
	io.Reader
	closed   bool
	closeErr error
}

func (s *trackedStream) Close() error { s.closed = true; return s.closeErr }

func refFor(value string) artifact.PayloadRef {
	return artifact.PayloadRef{Name: "content", MediaType: "application/octet-stream", Size: uint64(len(value)), Digest: digest.FromString(value)}
}

func TestCopyVerification(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name   string
		value  string
		mutate func(*artifact.PayloadRef)
		want   error
	}{
		{"valid", "plaintext", nil, nil},
		{"empty", "", nil, nil},
		{"truncated", "plaintext", func(p *artifact.PayloadRef) { p.Size++ }, ErrSizeMismatch},
		{"excess", "plaintext", func(p *artifact.PayloadRef) { p.Size-- }, ErrSizeMismatch},
		{"unexpected byte", "a", func(p *artifact.PayloadRef) { p.Size = 0 }, ErrSizeMismatch},
		{"digest mismatch", "plaintext", func(p *artifact.PayloadRef) { p.Digest = digest.FromString("corrupted") }, ErrDigestMismatch},
		{"uint64 size", "plaintext", func(p *artifact.PayloadRef) { p.Size = math.MaxUint64 }, ErrSizeMismatch},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ref := refFor(tc.value)
			if tc.mutate != nil {
				tc.mutate(&ref)
			}
			stream := &trackedStream{Reader: bytes.NewBufferString(tc.value)}
			source := sourceFunc(func(ctx context.Context, d digest.Digest) (io.ReadCloser, error) {
				if d != ref.Digest {
					t.Fatal("wrong digest requested")
				}
				return stream, nil
			})
			var dst bytes.Buffer
			err := Copy(context.Background(), &dst, source, ref)
			if !errors.Is(err, tc.want) {
				t.Fatalf("Copy = %v, want %v", err, tc.want)
			}
			if !stream.closed {
				t.Fatal("source was not closed")
			}
			if tc.want == nil && dst.String() != tc.value {
				t.Fatal("content changed")
			}
			if uint64(dst.Len()) > ref.Size {
				t.Fatal("wrote excess content")
			}
		})
	}
}

type readerFunc func([]byte) (int, error)

func (f readerFunc) Read(p []byte) (int, error) { return f(p) }

type writerFunc func([]byte) (int, error)

func (f writerFunc) Write(p []byte) (int, error) { return f(p) }

func TestCopyFailuresAndClose(t *testing.T) {
	t.Parallel()
	failure := errors.New("stream failure")
	for _, tc := range []struct {
		name     string
		reader   io.Reader
		writer   io.Writer
		closeErr error
		want     error
	}{
		{"read error", readerFunc(func(p []byte) (int, error) { p[0] = 'x'; return 1, failure }), io.Discard, nil, failure},
		{"write error", bytes.NewBufferString("x"), writerFunc(func([]byte) (int, error) { return 0, failure }), nil, failure},
		{"short write", bytes.NewBufferString("x"), writerFunc(func([]byte) (int, error) { return 0, nil }), nil, io.ErrShortWrite},
		{"close error", bytes.NewBufferString("x"), io.Discard, failure, failure},
		{"no progress", readerFunc(func([]byte) (int, error) { return 0, nil }), io.Discard, nil, io.ErrNoProgress},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stream := &trackedStream{Reader: tc.reader, closeErr: tc.closeErr}
			err := Copy(context.Background(), tc.writer, sourceFunc(func(context.Context, digest.Digest) (io.ReadCloser, error) { return stream, nil }), refFor("x"))
			if !errors.Is(err, tc.want) {
				t.Fatalf("Copy = %v, want %v", err, tc.want)
			}
			if !stream.closed {
				t.Fatal("source was not closed")
			}
		})
	}
	t.Run("open error", func(t *testing.T) {
		err := Copy(context.Background(), io.Discard, sourceFunc(func(context.Context, digest.Digest) (io.ReadCloser, error) { return nil, failure }), refFor("x"))
		if !errors.Is(err, failure) {
			t.Fatal(err)
		}
	})
	t.Run("invalid reference", func(t *testing.T) {
		ref := refFor("x")
		ref.Digest = "sha256:bad"
		err := Copy(context.Background(), io.Discard, sourceFunc(func(context.Context, digest.Digest) (io.ReadCloser, error) {
			t.Fatal("opened invalid reference")
			return nil, nil
		}), ref)
		if !errors.Is(err, artifact.ErrInvalidArtifact) {
			t.Fatal(err)
		}
	})
	t.Run("data and EOF", func(t *testing.T) {
		stream := &trackedStream{Reader: readerFunc(func(p []byte) (int, error) { p[0] = 'x'; return 1, io.EOF })}
		var dst bytes.Buffer
		if err := Copy(context.Background(), &dst, sourceFunc(func(context.Context, digest.Digest) (io.ReadCloser, error) { return stream, nil }), refFor("x")); err != nil {
			t.Fatal(err)
		}
		if dst.String() != "x" || !stream.closed {
			t.Fatal("final bytes lost or stream not closed")
		}
	})
}

func TestCopyCancellation(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	source := sourceFunc(func(context.Context, digest.Digest) (io.ReadCloser, error) {
		t.Fatal("opened after cancellation")
		return nil, nil
	})
	if err := Copy(ctx, io.Discard, source, refFor("x")); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	ctx, cancel = context.WithCancel(context.Background())
	defer cancel()
	stream := &trackedStream{Reader: readerFunc(func(p []byte) (int, error) { cancel(); p[0] = 'x'; return 1, nil })}
	source = sourceFunc(func(context.Context, digest.Digest) (io.ReadCloser, error) { return stream, nil })
	var dst bytes.Buffer
	if err := Copy(ctx, &dst, source, refFor("x")); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if dst.Len() != 0 || !stream.closed {
		t.Fatal("wrote after cancellation or leaked source")
	}
}

// A generated stream and rejecting sink prove memory does not grow with payload
// size. No payload-sized allocation is used by either fixture or Copy.
type generatedReader struct {
	remaining uint64
	maxRead   int
}

func (r *generatedReader) Read(p []byte) (int, error) {
	if len(p) > r.maxRead {
		r.maxRead = len(p)
	}
	if r.remaining == 0 {
		return 0, io.EOF
	}
	n := len(p)
	if uint64(n) > r.remaining {
		n = int(r.remaining)
	}
	clear(p[:n])
	r.remaining -= uint64(n)
	return n, nil
}

func TestCopyLargeStream(t *testing.T) {
	t.Parallel()
	const size = 10 * 1024 * 1024
	hash := digest.SHA256.Digester()
	_, err := io.Copy(hash.Hash(), &generatedReader{remaining: size})
	if err != nil {
		t.Fatal(err)
	}
	stream := &trackedStream{Reader: &generatedReader{remaining: size}}
	reader := stream.Reader.(*generatedReader)
	var count uint64
	sink := writerFunc(func(p []byte) (int, error) {
		if len(p) > 32*1024 {
			t.Fatal("unbounded write")
		}
		count += uint64(len(p))
		return len(p), nil
	})
	ref := artifact.PayloadRef{Name: "large", MediaType: "application/octet-stream", Digest: hash.Digest(), Size: size}
	if err := Copy(context.Background(), sink, sourceFunc(func(context.Context, digest.Digest) (io.ReadCloser, error) { return stream, nil }), ref); err != nil {
		t.Fatal(err)
	}
	if count != size || reader.maxRead > 32*1024 || !stream.closed {
		t.Fatal("streaming contract violated")
	}
}
