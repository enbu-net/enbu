// Package content streams plaintext payloads independently of Artifact IR and storage.
package content

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/enbu-net/enbu/pkg/artifact"
	"github.com/opencontainers/go-digest"
)

var (
	ErrSizeMismatch   = errors.New("payload size mismatch")
	ErrDigestMismatch = errors.New("payload digest mismatch")
)

// VerifyCopy streams plaintext from src to dst and verifies its size and SHA-256.
// Both streams are borrowed; the caller owns opening and closing them, and
// resolving or decrypting the source independently of the plaintext digest.
// Bytes written before success are unverified: callers must stage them and only
// publish/use the destination after VerifyCopy returns nil.
// Cancellation is checked between reads and writes. The caller must arrange
// interruption of blocking I/O when required.
func VerifyCopy(ctx context.Context, dst io.Writer, src io.Reader, ref artifact.PayloadRef) error {
	if err := ref.Validate(); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	hash := digest.SHA256.Digester()
	remaining := ref.Size
	buffer := make([]byte, 32*1024)
	emptyReads := 0
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		chunk := buffer
		// Probe one byte beyond the declared size, without int64 size conversion
		// or uint64 overflow. Excess content is never written to the destination.
		if remaining < uint64(len(chunk)) {
			chunk = chunk[:int(remaining)+1]
		}
		n, readErr := src.Read(chunk)
		if uint64(n) > remaining {
			return ErrSizeMismatch
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if n > 0 {
			emptyReads = 0
			written, writeErr := dst.Write(chunk[:n])
			if writeErr != nil {
				return fmt.Errorf("write payload: %w", writeErr)
			}
			if written != n {
				return io.ErrShortWrite
			}
			_, _ = hash.Hash().Write(chunk[:n])
			remaining -= uint64(n)
		} else if readErr == nil {
			emptyReads++
			if emptyReads >= 100 {
				return io.ErrNoProgress
			}
		}
		if readErr != nil {
			if !errors.Is(readErr, io.EOF) {
				return fmt.Errorf("read payload: %w", readErr)
			}
			if remaining != 0 {
				return ErrSizeMismatch
			}
			if hash.Digest() != ref.Digest {
				return ErrDigestMismatch
			}
			return ctx.Err()
		}
	}
}
