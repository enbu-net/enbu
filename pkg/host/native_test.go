package host

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestNativeCapabilityConstructorsRequireAbsoluteCleanPaths(t *testing.T) {
	directory := t.TempDir()
	unclean := directory + string(os.PathSeparator) + "." + string(os.PathSeparator) + "secret"
	invalid := []string{"", "relative", unclean, directory + "\x00secret"}
	for _, path := range invalid {
		if _, err := NewFileInput(path); !errors.Is(err, ErrUnsafeFileInput) {
			t.Fatalf("NewFileInput(%q) error = %v", path, err)
		}
		if _, err := NewSecureFileOutput(path); !errors.Is(err, ErrUnsafeFileOutput) {
			t.Fatalf("NewSecureFileOutput(%q) error = %v", path, err)
		}
	}
}

func TestFileInputReturnsPinnedReader(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "secret")
	if err := os.WriteFile(path, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	input, err := NewFileInput(path)
	if err != nil {
		t.Fatal(err)
	}
	reader, err := input.Open(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = reader.Close() }()

	moved := filepath.Join(directory, "moved")
	if err := os.Rename(path, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("replacement"), 0o600); err != nil {
		t.Fatal(err)
	}
	contents, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	if string(contents) != "original" {
		t.Fatalf("pinned contents = %q", contents)
	}
}

func TestFileInputRejectsNonRegularAndUnavailableFiles(t *testing.T) {
	directory := t.TempDir()
	for _, path := range []string{directory, filepath.Join(directory, "missing")} {
		input, err := NewFileInput(path)
		if err != nil {
			t.Fatal(err)
		}
		_, err = input.Open(context.Background())
		if !errors.Is(err, ErrUnsafeFileInput) {
			t.Fatalf("Open(%q) error = %v", path, err)
		}
		if strings.Contains(err.Error(), path) {
			t.Fatalf("Open error exposed input path: %v", err)
		}
	}
}

func TestFileInputHonorsCancellation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(path, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	input, err := NewFileInput(path)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := input.Open(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled Open error = %v", err)
	}
}

func TestFileInputCanBeOpenedConcurrently(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(path, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	input, err := NewFileInput(path)
	if err != nil {
		t.Fatal(err)
	}

	const readers = 32
	var wait sync.WaitGroup
	for range readers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			reader, openErr := input.Open(context.Background())
			if openErr != nil {
				t.Errorf("Open: %v", openErr)
				return
			}
			defer func() { _ = reader.Close() }()
			contents, readErr := io.ReadAll(reader)
			if readErr != nil {
				t.Errorf("ReadAll: %v", readErr)
			} else if string(contents) != "secret" {
				t.Errorf("contents = %q", contents)
			}
		}()
	}
	wait.Wait()
}

func TestSecureFileOutputCommitAndAbortAreTransactional(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "materialized.env")
	if err := os.WriteFile(path, []byte("OLD=value\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	output, err := NewSecureFileOutput(path)
	if err != nil {
		t.Fatal(err)
	}

	aborted, err := output.Open(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := aborted.Write([]byte("PARTIAL=value\n")); err != nil {
		t.Fatal(err)
	}
	if err := aborted.Abort(); err != nil {
		t.Fatal(err)
	}
	assertFileContents(t, path, "OLD=value\n")

	committed, err := output.Open(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := committed.Write([]byte("NEW=value\n")); err != nil {
		t.Fatal(err)
	}
	if err := committed.Commit(); err != nil {
		t.Fatal(err)
	}
	assertFileContents(t, path, "NEW=value\n")
	if err := committed.Abort(); err != nil {
		t.Fatalf("Abort after Commit: %v", err)
	}
}

func TestSecureFileOutputHonorsCancellation(t *testing.T) {
	output, err := NewSecureFileOutput(filepath.Join(t.TempDir(), "secret"))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := output.Open(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled Open error = %v", err)
	}
}

func assertFileContents(t *testing.T, path, want string) {
	t.Helper()
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(contents) != want {
		t.Fatalf("contents = %q, want %q", contents, want)
	}
}
