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

type trackedStream struct {
	io.Reader
	closed bool
}

func (s *trackedStream) Close() error { s.closed = true; return nil }

func refFor(value string) artifact.PayloadRef {
	return artifact.PayloadRef{Name: "content", MediaType: "application/octet-stream", Size: uint64(len(value)), Digest: digest.FromString(value)}
}

func TestVerifyCopyVerification(t *testing.T) {
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
			var dst bytes.Buffer
			err := VerifyCopy(context.Background(), &dst, stream, ref)
			if !errors.Is(err, tc.want) {
				t.Fatalf("VerifyCopy = %v, want %v", err, tc.want)
			}
			if stream.closed {
				t.Fatal("borrowed source was closed")
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

func TestVerifyCopyFailuresAndBorrowedStream(t *testing.T) {
	t.Parallel()
	failure := errors.New("stream failure")
	for _, tc := range []struct {
		name   string
		reader io.Reader
		writer io.Writer
		want   error
	}{
		{"read error", readerFunc(func(p []byte) (int, error) { p[0] = 'x'; return 1, failure }), io.Discard, failure},
		{"write error", bytes.NewBufferString("x"), writerFunc(func([]byte) (int, error) { return 0, failure }), failure},
		{"short write", bytes.NewBufferString("x"), writerFunc(func([]byte) (int, error) { return 0, nil }), io.ErrShortWrite},
		{"no progress", readerFunc(func([]byte) (int, error) { return 0, nil }), io.Discard, io.ErrNoProgress},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stream := &trackedStream{Reader: tc.reader}
			err := VerifyCopy(context.Background(), tc.writer, stream, refFor("x"))
			if !errors.Is(err, tc.want) {
				t.Fatalf("VerifyCopy = %v, want %v", err, tc.want)
			}
			if stream.closed {
				t.Fatal("borrowed source was closed")
			}
		})
	}
	t.Run("invalid reference", func(t *testing.T) {
		ref := refFor("x")
		ref.Digest = "sha256:bad"
		err := VerifyCopy(context.Background(), io.Discard, readerFunc(func([]byte) (int, error) {
			t.Fatal("read invalid reference")
			return 0, nil
		}), ref)
		if !errors.Is(err, artifact.ErrInvalidArtifact) {
			t.Fatal(err)
		}
	})
	t.Run("data and EOF", func(t *testing.T) {
		stream := &trackedStream{Reader: readerFunc(func(p []byte) (int, error) { p[0] = 'x'; return 1, io.EOF })}
		var dst bytes.Buffer
		if err := VerifyCopy(context.Background(), &dst, stream, refFor("x")); err != nil {
			t.Fatal(err)
		}
		if dst.String() != "x" || stream.closed {
			t.Fatal("final bytes lost or borrowed stream closed")
		}
	})
}

func TestVerifyCopyCancellation(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	source := readerFunc(func([]byte) (int, error) {
		t.Fatal("read after cancellation")
		return 0, nil
	})
	if err := VerifyCopy(ctx, io.Discard, source, refFor("x")); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	ctx, cancel = context.WithCancel(context.Background())
	defer cancel()
	stream := &trackedStream{Reader: readerFunc(func(p []byte) (int, error) { cancel(); p[0] = 'x'; return 1, nil })}
	var dst bytes.Buffer
	if err := VerifyCopy(ctx, &dst, stream, refFor("x")); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if dst.Len() != 0 || stream.closed {
		t.Fatal("wrote after cancellation or closed borrowed source")
	}
}

// A generated stream and rejecting sink prove memory does not grow with payload
// size. No payload-sized allocation is used by either fixture or VerifyCopy.
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

func TestVerifyCopyLargeStream(t *testing.T) {
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
	if err := VerifyCopy(context.Background(), sink, stream, ref); err != nil {
		t.Fatal(err)
	}
	if count != size || reader.maxRead > 32*1024 || stream.closed {
		t.Fatal("streaming contract violated")
	}
}
