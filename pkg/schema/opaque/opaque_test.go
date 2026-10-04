package opaque_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"math/rand/v2"
	"runtime"
	"testing"

	"github.com/enbu-net/enbu/pkg/artifact"
	"github.com/enbu-net/enbu/pkg/content"
	"github.com/enbu-net/enbu/pkg/schema/opaque"
	"github.com/opencontainers/go-digest"
)

func makeArtifact(t *testing.T, data []byte) artifact.Artifact {
	t.Helper()
	ref, err := opaque.PayloadRef("application/octet-stream; version=1", uint64(len(data)), digest.FromBytes(data))
	if err != nil {
		t.Fatal(err)
	}
	return artifact.Artifact{APIVersion: artifact.APIVersion, UID: "019c6e27-e55b-73d1-87d8-4e01f1f75043", Schema: opaque.Schema(), Metadata: artifact.Metadata{Name: "binary"}, Payloads: []artifact.PayloadRef{ref}}
}

func TestRoundTrip(t *testing.T) {
	random := make([]byte, 4096)
	r := rand.New(rand.NewPCG(1, 2))
	for i := range random {
		random[i] = byte(r.Uint32())
	}
	for _, data := range [][]byte{nil, {0, 1, 0, 2}, {0xff, 0xfe, 0x80}, random} {
		a := makeArtifact(t, data)
		var dst bytes.Buffer
		if err := opaque.VerifyArtifact(context.Background(), a, &dst, bytes.NewReader(data)); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(dst.Bytes(), data) {
			t.Fatal("bytes changed")
		}
		if a.Payloads[0].MediaType != "application/octet-stream; version=1" {
			t.Fatal("media type changed")
		}
	}
}

func TestRejectInvalidArtifact(t *testing.T) {
	tests := []struct {
		name   string
		change func(*artifact.Artifact)
		want   error
	}{
		{"wrong schema", func(a *artifact.Artifact) { a.Schema.Kind = "SecretMap" }, opaque.ErrUnsupportedSchema},
		{"zero payload", func(a *artifact.Artifact) { a.Payloads = nil }, opaque.ErrInvalidOpaque},
		{"multiple payloads", func(a *artifact.Artifact) {
			ref := a.Payloads[0]
			ref.Name = "extra"
			a.Payloads = append(a.Payloads, ref)
		}, opaque.ErrInvalidOpaque},
		{"wrong name", func(a *artifact.Artifact) { a.Payloads[0].Name = "other" }, opaque.ErrInvalidOpaque},
		{"invalid media type", func(a *artifact.Artifact) { a.Payloads[0].MediaType = "bad media type" }, artifact.ErrInvalidArtifact},
		{"invalid artifact", func(a *artifact.Artifact) { a.UID = "invalid" }, artifact.ErrInvalidArtifact},
		{"digest mismatch", func(a *artifact.Artifact) { a.Payloads[0].Digest = digest.FromString("other") }, content.ErrDigestMismatch},
		{"size too small", func(a *artifact.Artifact) { a.Payloads[0].Size-- }, content.ErrSizeMismatch},
		{"size too large", func(a *artifact.Artifact) { a.Payloads[0].Size++ }, content.ErrSizeMismatch},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := makeArtifact(t, []byte("abc"))
			tt.change(&a)
			if err := opaque.VerifyArtifact(context.Background(), a, io.Discard, bytes.NewBufferString("abc")); !errors.Is(err, tt.want) {
				t.Fatalf("got %v, want %v", err, tt.want)
			}
		})
	}
}

func TestPayloadRefValidation(t *testing.T) {
	for _, tt := range []struct {
		media string
		hash  digest.Digest
	}{
		{"", digest.FromString("")}, {"bad media type", digest.FromString("")}, {"application/octet-stream", "bad"},
	} {
		if _, err := opaque.PayloadRef(tt.media, 0, tt.hash); err == nil {
			t.Fatal("invalid ref accepted")
		}
	}
}

type borrowedReader struct {
	io.Reader
	closed bool
}

func (r *borrowedReader) Close() error { r.closed = true; return nil }

type borrowedWriter struct {
	io.Writer
	closed bool
}

func (w *borrowedWriter) Close() error { w.closed = true; return nil }

type errorReader struct{ err error }

func (r errorReader) Read([]byte) (int, error) { return 0, r.err }

type errorWriter struct{ err error }

func (w errorWriter) Write([]byte) (int, error) { return 0, w.err }

func TestStreamOwnershipAndFailures(t *testing.T) {
	sentinel := errors.New("stream failure")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, tt := range []struct {
		name string
		ctx  context.Context
		src  io.Reader
		dst  io.Writer
		want error
	}{
		{"success", context.Background(), bytes.NewBufferString("abc"), io.Discard, nil},
		{"reader", context.Background(), errorReader{sentinel}, io.Discard, sentinel},
		{"writer", context.Background(), bytes.NewBufferString("abc"), errorWriter{sentinel}, sentinel},
		{"cancel", ctx, bytes.NewBufferString("abc"), io.Discard, context.Canceled},
	} {
		t.Run(tt.name, func(t *testing.T) {
			src := &borrowedReader{Reader: tt.src}
			dst := &borrowedWriter{Writer: tt.dst}
			err := opaque.VerifyArtifact(tt.ctx, makeArtifact(t, []byte("abc")), dst, src)
			if !errors.Is(err, tt.want) {
				t.Fatalf("got %v, want %v", err, tt.want)
			}
			if src.closed || dst.closed {
				t.Fatal("closed caller streams")
			}
		})
	}
}

// The stream and sink never retain the payload. Total allocations must remain
// far below its size, catching regressions that materialize the entire payload.
func TestLargeGeneratedStream(t *testing.T) {
	const size = 12 * 1024 * 1024
	// Repeat a fixed byte to make the hash independent of read chunk boundaries.
	hash := digest.SHA256.Digester()
	_, err := io.Copy(hash.Hash(), io.LimitReader(zeroReader{}, size))
	if err != nil {
		t.Fatal(err)
	}
	a := makeArtifact(t, nil)
	a.Payloads[0].Size = size
	a.Payloads[0].Digest = hash.Digest()
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	err = opaque.VerifyArtifact(context.Background(), a, io.Discard, io.LimitReader(zeroReader{}, size))
	runtime.ReadMemStats(&after)
	if err != nil {
		t.Fatal(err)
	}
	if allocated := after.TotalAlloc - before.TotalAlloc; allocated > 1024*1024 {
		t.Fatalf("allocated %d bytes for streaming payload", allocated)
	}
}

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) { clear(p); return len(p), nil }
