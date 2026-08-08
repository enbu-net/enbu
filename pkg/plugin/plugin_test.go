package plugin

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"testing"

	"github.com/opencontainers/go-digest"
)

// minimalTransform is a wasm module exporting enbu_transform() -> i32(0).
var minimalTransform = []byte{
	0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00,
	0x01, 0x05, 0x01, 0x60, 0x00, 0x01, 0x7f,
	0x03, 0x02, 0x01, 0x00,
	0x07, 0x12, 0x01, 0x0e, 'e', 'n', 'b', 'u', '_', 't', 'r', 'a', 'n', 's', 'f', 'o', 'r', 'm', 0x00, 0x00,
	0x0a, 0x06, 0x01, 0x04, 0x00, 0x41, 0x00, 0x0b,
}

func TestVerifyPackage(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pkg := Package{Module: minimalTransform, Digest: digest.FromBytes(minimalTransform)}
	pkg.Signature = ed25519.Sign(private, append([]byte(pluginDomain), minimalTransform...))
	if err := VerifyPackage(pkg, public); err != nil {
		t.Fatal(err)
	}
	pkg.Module = append([]byte(nil), minimalTransform...)
	pkg.Module[len(pkg.Module)-1]++
	if err := VerifyPackage(pkg, public); !errors.Is(err, ErrInvalidPackage) {
		t.Fatalf("tampered package error = %v", err)
	}
}

func TestHostExecutesWithoutWASIAndReturnsNoDrafts(t *testing.T) {
	host, err := NewHost(DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	drafts, err := host.Execute(context.Background(), minimalTransform, Input{Reader: readerAtString("input"), Size: 5})
	if err != nil {
		t.Fatal(err)
	}
	if len(drafts) != 0 {
		t.Fatalf("drafts = %#v", drafts)
	}
}

func TestHostRejectsUnknownImportsAndBoundsInput(t *testing.T) {
	host, err := NewHost(DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	unknown := append([]byte(nil), minimalTransform...)
	// A malformed module is rejected before any host function can be reached.
	unknown[8] = 0
	if _, err := host.Execute(context.Background(), unknown, Input{Reader: readerAtString(""), Size: 0}); !errors.Is(err, ErrInvalidPackage) {
		t.Fatalf("invalid module error = %v", err)
	}
	if _, err := host.Execute(context.Background(), minimalTransform, Input{Reader: readerAtString(""), Size: MaxInputBytes + 1}); !errors.Is(err, ErrLimit) {
		t.Fatalf("oversized input error = %v", err)
	}
}

type readerAtString string

func (reader readerAtString) ReadAt(p []byte, offset int64) (int, error) {
	if offset >= int64(len(reader)) {
		return 0, io.EOF
	}
	count := copy(p, reader[offset:])
	if count < len(p) {
		return count, io.EOF
	}
	return count, nil
}
