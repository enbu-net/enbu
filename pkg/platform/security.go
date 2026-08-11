// Package platform contains the small OS-neutral security boundary shared by
// the application host. It never handles plaintext secrets outside a caller-
// supplied stream; it provides private directories, atomic replacement, and
// process-local coordination primitives.
package platform

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
)

var (
	ErrUnsafePath      = errors.New("platform: unsafe path")
	ErrInsecureFile    = errors.New("platform: insecure file permissions")
	ErrAlreadyLocked   = errors.New("platform: lock already held")
	ErrDestinationBusy = errors.New("platform: destination is busy")
	ErrWriterClosed    = errors.New("platform: secure writer is closed")
)

// DataDir returns the per-user application data directory without consulting
// an untrusted project directory or environment variable. XDG_DATA_HOME is
// honored on Unix; UserConfigDir covers macOS and Windows native locations.
func DataDir() (string, error) {
	if runtime.GOOS != "windows" {
		if xdg := os.Getenv("XDG_DATA_HOME"); xdg != "" && filepath.IsAbs(xdg) {
			return filepath.Join(xdg, "enbu"), nil
		}
	}
	base, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("platform: user config dir: %w", err)
	}
	return filepath.Join(base, "enbu"), nil
}

// EnsurePrivateDir creates path when necessary and applies the native private
// directory policy to the final directory. Existing ancestors are validated
// but never have their permissions changed.
func EnsurePrivateDir(path string) error {
	canonical, err := CanonicalizeParentPath(path)
	if err != nil {
		return err
	}
	path = canonical
	if err := prepareDirectoryPath(path); err != nil {
		return err
	}
	return protectPrivateDirectory(path)
}

// prepareDirectoryPath validates every existing component and creates only
// missing components. Permissions are applied exclusively to directories this
// call successfully created; a concurrently-created component is treated as
// existing and is never chmoded or assigned a new DACL.
func prepareDirectoryPath(path string) error {
	if err := validateUsableAbsolute(path); err != nil {
		return err
	}
	if filepath.Dir(path) == path {
		return fmt.Errorf("%w: filesystem root cannot be a private directory", ErrUnsafePath)
	}
	for _, component := range absolutePathComponents(path) {
		info, err := os.Lstat(component)
		created := false
		if errors.Is(err, os.ErrNotExist) {
			err = os.Mkdir(component, 0o700)
			switch {
			case err == nil:
				created = true
			case errors.Is(err, os.ErrExist):
				// Another process won the creation race. Validate its
				// directory without changing its permissions.
			default:
				return fmt.Errorf("platform: create private directory component %q: %w", component, err)
			}
			info, err = os.Lstat(component)
		}
		if err != nil {
			return fmt.Errorf("platform: inspect directory component %q: %w", component, err)
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return fmt.Errorf("%w: directory component %q is a link or non-directory", ErrUnsafePath, component)
		}
		if err := rejectPlatformSpecial(component); err != nil {
			return err
		}
		if created {
			if err := protectPrivateDirectory(component); err != nil {
				return err
			}
		}
	}
	return validatePathComponents(path, false)
}

func protectPrivateDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("platform: inspect private directory: %w", err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%w: private directory is not a real directory", ErrUnsafePath)
	}
	directory, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("platform: open private directory: %w", err)
	}
	defer func() { _ = directory.Close() }()
	openedInfo, err := directory.Stat()
	if err != nil {
		return fmt.Errorf("platform: inspect opened private directory: %w", err)
	}
	if !os.SameFile(info, openedInfo) {
		return fmt.Errorf("%w: private directory changed while opening", ErrUnsafePath)
	}
	if err := protectOpenedFile(directory, path, true); err != nil {
		return fmt.Errorf("platform: protect directory: %w", errors.Join(ErrInsecureFile, err))
	}
	if err := validatePrivateOpenedFile(directory, true); err != nil {
		return err
	}
	return nil
}

type secureWriterState uint8

const (
	secureWriterOpen secureWriterState = iota
	secureWriterCommitted
	secureWriterAborted
)

type replaceFileFunc func(*os.Root, string, string) error
type syncDirectoryFunc func(*os.Root) error

// SecureWriter streams a replacement into a private same-directory temporary
// file. Commit syncs the data, atomically replaces the destination, and syncs
// the parent directory where the operating system supports it. Abort is
// idempotent and leaves the destination unchanged.
//
// Callers should defer Abort immediately after construction. Abort is a no-op
// after a successful Commit.
type SecureWriter struct {
	mu sync.Mutex

	file        *os.File
	root        *os.Root
	parentInfo  os.FileInfo
	tempInfo    os.FileInfo
	parentPath  string
	destination string
	tempName    string
	state       secureWriterState

	replace       replaceFileFunc
	syncDirectory syncDirectoryFunc
}

// NewSecureWriter prepares an atomic replacement for path. path must be an
// absolute, clean, non-root path with no existing symlink or platform-specific
// reparse component.
func NewSecureWriter(path string) (*SecureWriter, error) {
	canonical, err := CanonicalizeParentPath(path)
	if err != nil {
		return nil, err
	}
	path = canonical
	parentPath := filepath.Dir(path)
	if parentPath == path {
		return nil, fmt.Errorf("%w: destination cannot be a filesystem root", ErrUnsafePath)
	}
	if err := prepareDirectoryPath(parentPath); err != nil {
		return nil, err
	}

	parentInfo, err := os.Lstat(parentPath)
	if err != nil {
		return nil, fmt.Errorf("platform: inspect destination directory: %w", err)
	}
	root, err := os.OpenRoot(parentPath)
	if err != nil {
		return nil, fmt.Errorf("platform: pin destination directory: %w", err)
	}
	rootInfo, err := root.Stat(".")
	if err != nil {
		_ = root.Close()
		return nil, fmt.Errorf("platform: inspect pinned destination directory: %w", err)
	}
	if !os.SameFile(parentInfo, rootInfo) {
		_ = root.Close()
		return nil, fmt.Errorf("%w: destination directory changed while opening", ErrUnsafePath)
	}

	writer := &SecureWriter{
		root:          root,
		parentInfo:    rootInfo,
		parentPath:    parentPath,
		destination:   filepath.Base(path),
		state:         secureWriterOpen,
		replace:       replaceFile,
		syncDirectory: syncDirectory,
	}
	if err := writer.validateDestinationLocked(); err != nil {
		_ = writer.abortLocked()
		return nil, err
	}
	if err := writer.createTemporaryLocked(); err != nil {
		_ = writer.abortLocked()
		return nil, err
	}
	return writer, nil
}

// Write appends plaintext to the private temporary file. Write never makes the
// destination visible; only Commit does.
func (writer *SecureWriter) Write(data []byte) (int, error) {
	if writer == nil {
		return 0, ErrWriterClosed
	}
	writer.mu.Lock()
	defer writer.mu.Unlock()
	if writer.state != secureWriterOpen || writer.file == nil {
		return 0, ErrWriterClosed
	}
	return writer.file.Write(data)
}

// Commit durably flushes the temporary file and atomically replaces the
// destination. Every failure before replacement aborts the writer and removes
// the temporary file. Once replacement succeeds, a later parent-sync error is
// returned but the writer remains committed because rollback would not be
// atomic.
func (writer *SecureWriter) Commit() error {
	if writer == nil {
		return ErrWriterClosed
	}
	writer.mu.Lock()
	defer writer.mu.Unlock()
	if writer.state != secureWriterOpen || writer.file == nil || writer.root == nil {
		return ErrWriterClosed
	}

	if err := writer.file.Sync(); err != nil {
		return writer.failLocked(fmt.Errorf("platform: sync secure temporary file: %w", err))
	}
	if err := writer.file.Close(); err != nil {
		writer.file = nil
		return writer.failLocked(fmt.Errorf("platform: close secure temporary file: %w", err))
	}
	writer.file = nil

	if err := writer.validatePinnedParentLocked(); err != nil {
		return writer.failLocked(err)
	}
	if err := writer.validateTemporaryLocked(); err != nil {
		return writer.failLocked(err)
	}
	if err := writer.validateDestinationLocked(); err != nil {
		return writer.failLocked(err)
	}
	if err := writer.replace(writer.root, writer.tempName, writer.destination); err != nil {
		return writer.failLocked(fmt.Errorf("platform: atomically replace destination: %w", err))
	}

	writer.tempName = ""
	writer.state = secureWriterCommitted
	if err := writer.syncDirectory(writer.root); err != nil {
		_ = writer.root.Close()
		writer.root = nil
		return fmt.Errorf("platform: sync destination directory: %w", err)
	}
	_ = writer.root.Close()
	writer.root = nil
	return nil
}

// Abort closes and removes the temporary file. It is safe to call repeatedly
// and after Commit.
func (writer *SecureWriter) Abort() error {
	if writer == nil {
		return nil
	}
	writer.mu.Lock()
	defer writer.mu.Unlock()
	if writer.state != secureWriterOpen {
		return nil
	}
	return writer.abortLocked()
}

func (writer *SecureWriter) createTemporaryLocked() error {
	for range 128 {
		random := make([]byte, 16)
		if _, err := rand.Read(random); err != nil {
			return fmt.Errorf("platform: generate secure temporary name: %w", err)
		}
		name := "." + writer.destination + ".enbu-" + hex.EncodeToString(random) + ".tmp"
		file, err := writer.root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if errors.Is(err, os.ErrExist) {
			continue
		}
		if err != nil {
			return fmt.Errorf("platform: create secure temporary file: %w", err)
		}
		writer.file = file
		writer.tempName = name
		if err := protectOpenedFile(file, filepath.Join(writer.parentPath, name), false); err != nil {
			return fmt.Errorf("platform: protect temporary file: %w", errors.Join(ErrInsecureFile, err))
		}
		info, err := file.Stat()
		if err != nil {
			return fmt.Errorf("platform: inspect secure temporary file: %w", err)
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("%w: temporary file is not regular", ErrUnsafePath)
		}
		if err := validatePrivateOpenedFile(file, false); err != nil {
			return err
		}
		writer.tempInfo = info
		return nil
	}
	return fmt.Errorf("platform: create secure temporary file: too many name collisions")
}

func (writer *SecureWriter) validatePinnedParentLocked() error {
	if err := validatePathComponents(writer.parentPath, false); err != nil {
		return err
	}
	current, err := os.Lstat(writer.parentPath)
	if err != nil {
		return fmt.Errorf("platform: inspect destination directory before commit: %w", err)
	}
	pinned, err := writer.root.Stat(".")
	if err != nil {
		return fmt.Errorf("platform: inspect pinned destination directory before commit: %w", err)
	}
	if !current.IsDir() || !os.SameFile(current, writer.parentInfo) || !os.SameFile(pinned, writer.parentInfo) {
		return fmt.Errorf("%w: destination directory changed before commit", ErrUnsafePath)
	}
	return nil
}

func (writer *SecureWriter) validateTemporaryLocked() error {
	info, err := writer.root.Lstat(writer.tempName)
	if err != nil {
		return fmt.Errorf("platform: inspect secure temporary file before commit: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || !os.SameFile(info, writer.tempInfo) {
		return fmt.Errorf("%w: secure temporary file changed before commit", ErrUnsafePath)
	}
	return nil
}

func (writer *SecureWriter) validateDestinationLocked() error {
	info, err := writer.root.Lstat(writer.destination)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("platform: inspect destination: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return fmt.Errorf("%w: destination is not a regular file", ErrUnsafePath)
	}
	fullPath := filepath.Join(writer.parentPath, writer.destination)
	if err := rejectPlatformSpecial(fullPath); err != nil {
		return err
	}
	return nil
}

func (writer *SecureWriter) failLocked(primary error) error {
	cleanupErr := writer.abortLocked()
	if cleanupErr != nil {
		return errors.Join(primary, cleanupErr)
	}
	return primary
}

func (writer *SecureWriter) abortLocked() error {
	var failures []error
	if writer.file != nil {
		if err := writer.file.Close(); err != nil {
			failures = append(failures, fmt.Errorf("platform: close secure temporary file: %w", err))
		}
		writer.file = nil
	}
	if writer.root != nil && writer.tempName != "" {
		if err := writer.root.Remove(writer.tempName); err != nil && !errors.Is(err, os.ErrNotExist) {
			failures = append(failures, fmt.Errorf("platform: remove secure temporary file: %w", err))
		}
		writer.tempName = ""
	}
	if writer.root != nil {
		if err := writer.root.Close(); err != nil {
			failures = append(failures, fmt.Errorf("platform: close destination directory: %w", err))
		}
		writer.root = nil
	}
	writer.state = secureWriterAborted
	return errors.Join(failures...)
}

// Lock is process-local and intentionally does not pretend to coordinate
// remote clients. It protects local configuration and materialization only.
type Lock struct {
	mu sync.Mutex
}

func (lock *Lock) Acquire() func() {
	lock.mu.Lock()
	return lock.mu.Unlock
}

// ValidatePrivateFile verifies that path is a real regular file protected by
// the native private-file policy.
func ValidatePrivateFile(path string) error {
	canonical, err := CanonicalizeParentPath(path)
	if err != nil {
		return err
	}
	path = canonical
	if err := validatePathComponents(path, false); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return fmt.Errorf("%w: not a regular file", ErrUnsafePath)
	}
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("platform: open private file: %w", err)
	}
	defer func() { _ = file.Close() }()
	openedInfo, err := file.Stat()
	if err != nil {
		return fmt.Errorf("platform: inspect opened private file: %w", err)
	}
	if !os.SameFile(info, openedInfo) {
		return fmt.Errorf("%w: private file changed while opening", ErrUnsafePath)
	}
	return validatePrivateOpenedFile(file, false)
}

// CanonicalizeParentPath resolves only operating-system-owned path aliases in
// the parent portion of path. It never resolves the final component, so a
// caller-supplied symlink or reparse target remains rejectable by the pinned
// open that follows. On macOS this makes the immutable /var, /tmp, and /etc
// aliases usable without weakening the rule for arbitrary symlinks.
func CanonicalizeParentPath(path string) (string, error) {
	if err := validateUsableAbsolute(path); err != nil {
		return "", err
	}
	canonical, err := canonicalizeParentPath(path)
	if err != nil {
		return "", err
	}
	if err := validateUsableAbsolute(canonical); err != nil {
		return "", err
	}
	return canonical, nil
}

func validateUsableAbsolute(path string) error {
	if path == "" || strings.IndexByte(path, 0) >= 0 || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return fmt.Errorf("%w: path must be absolute, clean, and NUL-free", ErrUnsafePath)
	}
	if err := validatePlatformPath(path); err != nil {
		return err
	}
	return nil
}

// validatePathComponents rejects links and native reparse points in every
// existing component. When allowMissing is true, the first missing component
// ends validation so that MkdirAll may create the remaining suffix.
func validatePathComponents(path string, allowMissing bool) error {
	components := absolutePathComponents(path)
	for index, component := range components {
		info, err := os.Lstat(component)
		if errors.Is(err, os.ErrNotExist) && allowMissing {
			return nil
		}
		if err != nil {
			return fmt.Errorf("platform: inspect path component %q: %w", component, err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%w: path component %q is a symbolic link", ErrUnsafePath, component)
		}
		if index < len(components)-1 && !info.IsDir() {
			return fmt.Errorf("%w: path component %q is not a directory", ErrUnsafePath, component)
		}
		if err := rejectPlatformSpecial(component); err != nil {
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

var _ io.Writer = (*SecureWriter)(nil)
