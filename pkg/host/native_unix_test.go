//go:build linux || darwin

package host

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/opencontainers/go-digest"
	"golang.org/x/sys/unix"
)

func TestFileInputRejectsSymbolicLinksInEveryComponent(t *testing.T) {
	directory := t.TempDir()
	targetDirectory := filepath.Join(directory, "target")
	if err := os.Mkdir(targetDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(targetDirectory, "secret")
	if err := os.WriteFile(target, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}

	finalLink := filepath.Join(directory, "secret-link")
	if err := os.Symlink(target, finalLink); err != nil {
		t.Fatal(err)
	}
	parentLink := filepath.Join(directory, "parent-link")
	if err := os.Symlink(targetDirectory, parentLink); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{finalLink, filepath.Join(parentLink, "secret")} {
		input, err := NewFileInput(path)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := input.Open(context.Background()); !errors.Is(err, ErrUnsafeFileInput) {
			t.Fatalf("Open(%q) error = %v", path, err)
		}
	}
}

func TestFileInputRejectsFIFOWithoutBlocking(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secret-fifo")
	if err := unix.Mkfifo(path, 0o600); err != nil {
		t.Fatal(err)
	}
	input, err := NewFileInput(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := input.Open(context.Background()); !errors.Is(err, ErrUnsafeFileInput) {
		t.Fatalf("FIFO Open error = %v", err)
	}
}

func TestSecureFileOutputRejectsSymbolicLinkDestination(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(directory, "target")
	if err := os.WriteFile(target, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(directory, "destination")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	output, err := NewSecureFileOutput(link)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := output.Open(context.Background()); !errors.Is(err, ErrUnsafeFileOutput) {
		t.Fatalf("symlink output error = %v", err)
	}
	assertFileContents(t, target, "old")
}

func TestOpenWorkspaceRejectsSymbolicLinkRoot(t *testing.T) {
	host := newTestHost(t, executorFunc(func(context.Context, Execution, Action) (Outcome, error) {
		return Outcome{}, nil
	}))
	target := t.TempDir()
	link := filepath.Join(t.TempDir(), "workspace")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	_, err := host.OpenWorkspace(context.Background(), OpenWorkspaceRequest{
		WorkspaceID: testWorkspaceID, Root: link, ConfigRevision: testDigest("config"),
	})
	if !errors.Is(err, ErrInvalidWorkspace) {
		t.Fatalf("symlink workspace error = %v", err)
	}
}

func testDigest(value string) digest.Digest {
	return digest.FromString(value)
}
