package host

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/enbu-net/enbu/pkg/platform"
)

var (
	ErrUnsafeFileInput  = errors.New("host: unsafe file input")
	ErrUnsafeFileOutput = errors.New("host: unsafe file output")
)

// FileInput is a native, path-backed input capability. Its path is captured
// when the capability is constructed, but the filesystem is inspected only
// when Open claims it. Open returns an already-open regular file whose native
// identity is independent of later path replacement.
//
// FileInput intentionally exposes neither the path nor a byte/string helper.
// Plaintext enters the executor only through the returned reader.
type FileInput struct {
	path string
}

// NewFileInput captures an absolute, clean native path. The path may disappear
// or change before use; Open performs the authoritative safety checks.
func NewFileInput(path string) (*FileInput, error) {
	canonical, err := platform.CanonicalizeParentPath(path)
	if err != nil {
		return nil, newCapabilityError(ErrUnsafeFileInput, "capture path", err)
	}
	if err := validateCapabilityPath(canonical); err != nil {
		return nil, newCapabilityError(ErrUnsafeFileInput, "capture path", err)
	}
	return &FileInput{path: canonical}, nil
}

// Open pins and returns the regular file currently named by the captured path.
// Symbolic links, Windows reparse points, non-regular files, and path changes
// during acquisition fail closed.
func (input *FileInput) Open(ctx context.Context) (io.ReadCloser, error) {
	if input == nil || input.path == "" {
		return nil, newCapabilityError(ErrUnsafeFileInput, "open", nil)
	}
	if ctx == nil {
		return nil, newCapabilityError(ErrUnsafeFileInput, "open", errors.New("nil context"))
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	file, err := openPinnedRegularFile(input.path)
	if err != nil {
		return nil, newCapabilityError(ErrUnsafeFileInput, "open", err)
	}
	if err := ctx.Err(); err != nil {
		_ = file.Close()
		return nil, err
	}
	return file, nil
}

// SecureFileOutput is a native, path-backed transactional output capability.
// Open delegates temporary-file protection and atomic replacement to platform.
// The destination remains unchanged unless the host commits the returned
// writer after a successful operation.
type SecureFileOutput struct {
	path string
}

// NewSecureFileOutput captures an absolute, clean native destination path.
func NewSecureFileOutput(path string) (*SecureFileOutput, error) {
	canonical, err := platform.CanonicalizeParentPath(path)
	if err != nil {
		return nil, newCapabilityError(ErrUnsafeFileOutput, "capture path", err)
	}
	if err := validateCapabilityPath(canonical); err != nil {
		return nil, newCapabilityError(ErrUnsafeFileOutput, "capture path", err)
	}
	if filepath.Dir(canonical) == canonical {
		return nil, newCapabilityError(ErrUnsafeFileOutput, "capture path", errors.New("filesystem root"))
	}
	return &SecureFileOutput{path: canonical}, nil
}

// Open creates a private, same-directory temporary writer. Callers cannot
// commit it directly through Execution; commit/abort remains host-owned.
func (output *SecureFileOutput) Open(ctx context.Context) (Output, error) {
	if output == nil || output.path == "" {
		return nil, newCapabilityError(ErrUnsafeFileOutput, "open", nil)
	}
	if ctx == nil {
		return nil, newCapabilityError(ErrUnsafeFileOutput, "open", errors.New("nil context"))
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	writer, err := platform.NewSecureWriter(output.path)
	if err != nil {
		return nil, newCapabilityError(ErrUnsafeFileOutput, "open", err)
	}
	if err := ctx.Err(); err != nil {
		_ = writer.Abort()
		return nil, err
	}
	return writer, nil
}

func validateCapabilityPath(path string) error {
	if path == "" || strings.IndexByte(path, 0) >= 0 || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return errors.New("path must be absolute, clean, and NUL-free")
	}
	return validateNativePath(path)
}

func openPinnedRegularFile(path string) (*os.File, error) {
	if err := validateExistingPathComponents(path); err != nil {
		return nil, err
	}

	parentPath := filepath.Dir(path)
	parentBefore, err := os.Lstat(parentPath)
	if err != nil {
		return nil, err
	}
	if !parentBefore.IsDir() || parentBefore.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("input parent is not a real directory")
	}

	root, err := os.OpenRoot(parentPath)
	if err != nil {
		return nil, err
	}
	defer func() { _ = root.Close() }()
	rootInfo, err := root.Stat(".")
	if err != nil {
		return nil, err
	}
	if !rootInfo.IsDir() || !os.SameFile(parentBefore, rootInfo) {
		return nil, errors.New("input parent changed while opening")
	}

	name := filepath.Base(path)
	before, err := root.Lstat(name)
	if err != nil {
		return nil, err
	}
	if before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() {
		return nil, errors.New("input is not a real regular file")
	}
	if err := rejectNativeSpecial(path); err != nil {
		return nil, err
	}

	file, err := openNativeNoFollow(root, name)
	if err != nil {
		return nil, err
	}
	keep := false
	defer func() {
		if !keep {
			_ = file.Close()
		}
	}()

	opened, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !opened.Mode().IsRegular() {
		return nil, errors.New("opened input is not a regular file")
	}
	if err := rejectOpenedNativeSpecial(file); err != nil {
		return nil, err
	}
	after, err := root.Lstat(name)
	if err != nil {
		return nil, err
	}
	if after.Mode()&os.ModeSymlink != 0 || !after.Mode().IsRegular() ||
		!os.SameFile(before, opened) || !os.SameFile(after, opened) {
		return nil, errors.New("input changed while opening")
	}
	if err := validateExistingPathComponents(path); err != nil {
		return nil, err
	}
	parentAfter, err := os.Lstat(parentPath)
	if err != nil {
		return nil, err
	}
	if !os.SameFile(parentAfter, rootInfo) {
		return nil, errors.New("input parent changed while opening")
	}

	keep = true
	return file, nil
}

func validatePinnedDirectory(path string) error {
	if err := validateExistingPathComponents(path); err != nil {
		return err
	}
	before, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !before.IsDir() || before.Mode()&os.ModeSymlink != 0 {
		return errors.New("path is not a real directory")
	}

	root, err := os.OpenRoot(path)
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()
	openedFile, err := root.Open(".")
	if err != nil {
		return err
	}
	defer func() { _ = openedFile.Close() }()
	opened, err := openedFile.Stat()
	if err != nil {
		return err
	}
	if !opened.IsDir() || !os.SameFile(before, opened) {
		return errors.New("directory changed while opening")
	}
	if err := rejectOpenedNativeSpecial(openedFile); err != nil {
		return err
	}
	if err := validateExistingPathComponents(path); err != nil {
		return err
	}
	after, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !after.IsDir() || !os.SameFile(after, opened) {
		return errors.New("directory changed while opening")
	}
	return nil
}

func validateExistingPathComponents(path string) error {
	components := absolutePathComponents(path)
	if len(components) == 0 {
		return errors.New("filesystem root is not a capability target")
	}
	for index, component := range components {
		info, err := os.Lstat(component)
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return errors.New("path contains a symbolic link")
		}
		if index < len(components)-1 && !info.IsDir() {
			return errors.New("path contains a non-directory component")
		}
		if err := rejectNativeSpecial(component); err != nil {
			return err
		}
	}
	return nil
}

func absolutePathComponents(path string) []string {
	volume := filepath.VolumeName(path)
	remainder := strings.TrimPrefix(path, volume)
	remainder = strings.TrimLeft(remainder, string(os.PathSeparator))
	if remainder == "" {
		return nil
	}
	current := string(os.PathSeparator)
	if volume != "" {
		current = volume + string(os.PathSeparator)
	}
	parts := strings.Split(remainder, string(os.PathSeparator))
	components := make([]string, 0, len(parts))
	for _, part := range parts {
		if part == "" {
			continue
		}
		current = filepath.Join(current, part)
		components = append(components, current)
	}
	return components
}

type capabilityError struct {
	kind      error
	operation string
	cause     error
}

func newCapabilityError(kind error, operation string, cause error) error {
	return &capabilityError{kind: kind, operation: operation, cause: cause}
}

func (failure *capabilityError) Error() string {
	return fmt.Sprintf("%s: %s", failure.kind, failure.operation)
}

func (failure *capabilityError) Unwrap() []error {
	if failure.cause == nil {
		return []error{failure.kind}
	}
	return []error{failure.kind, failure.cause}
}

var (
	_ InputSource  = (*FileInput)(nil)
	_ OutputTarget = (*SecureFileOutput)(nil)
	_ Output       = (*platform.SecureWriter)(nil)
)
