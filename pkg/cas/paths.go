package cas

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/enbu-net/enbu/pkg/artifact"
	"github.com/opencontainers/go-digest"
)

const (
	dataDirectoryName       = "objects"
	descriptorDirectoryName = "descriptors"
	temporaryDirectoryName  = "tmp"
	algorithmDirectoryName  = "sha256"
)

func openManagedRoot(path string) (*os.Root, error) {
	root, err := os.OpenRoot(path)
	if err != nil {
		return nil, fmt.Errorf("open CAS root handle: %w", err)
	}
	opened, err := root.Stat(".")
	if err != nil {
		_ = root.Close()
		return nil, fmt.Errorf("stat opened CAS root: %w", err)
	}
	named, err := os.Lstat(path)
	if err != nil {
		_ = root.Close()
		return nil, fmt.Errorf("recheck CAS root path: %w", err)
	}
	if named.Mode()&os.ModeSymlink != 0 || !named.IsDir() || !opened.IsDir() || !os.SameFile(opened, named) {
		_ = root.Close()
		return nil, fmt.Errorf("%w: CAS root changed while its handle was opened", ErrUnsafePath)
	}
	return root, nil
}

func prepareRoot(root string) error {
	if info, err := os.Lstat(root); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return fmt.Errorf("%w: CAS root is a symlink or non-directory", ErrUnsafePath)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect CAS root: %w", err)
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return fmt.Errorf("create CAS root: %w", err)
	}
	info, err := os.Lstat(root)
	if err != nil {
		return fmt.Errorf("inspect CAS root: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("%w: CAS root is not a real directory", ErrUnsafePath)
	}
	if err := rejectPlatformSpecial(root); err != nil {
		return err
	}
	if err := os.Chmod(root, 0o700); err != nil {
		return fmt.Errorf("protect CAS root: %w", err)
	}
	return nil
}

// canonicalRootPath resolves symlinks in ancestors outside the CAS while
// retaining a not-yet-created suffix. A symlink at the requested root itself
// is rejected rather than silently selecting another store.
func canonicalRootPath(path string) (string, error) {
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return "", fmt.Errorf("%w: CAS root %q is a symlink", ErrUnsafePath, path)
		}
		if err := rejectPlatformSpecial(path); err != nil {
			return "", err
		}
		resolved, err := filepath.EvalSymlinks(path)
		if err != nil {
			return "", fmt.Errorf("resolve CAS root ancestors: %w", err)
		}
		return filepath.Clean(resolved), nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("inspect requested CAS root: %w", err)
	}

	current := path
	missing := make([]string, 0, 4)
	for {
		parent := filepath.Dir(current)
		if parent == current {
			return "", fmt.Errorf("resolve CAS root %q: no existing ancestor", path)
		}
		missing = append(missing, filepath.Base(current))
		current = parent
		if _, err := os.Lstat(current); err == nil {
			break
		} else if !errors.Is(err, os.ErrNotExist) {
			return "", fmt.Errorf("inspect CAS root ancestor %q: %w", current, err)
		}
	}
	resolved, err := filepath.EvalSymlinks(current)
	if err != nil {
		return "", fmt.Errorf("resolve CAS root ancestor %q: %w", current, err)
	}
	for i := len(missing) - 1; i >= 0; i-- {
		resolved = filepath.Join(resolved, missing[i])
	}
	return filepath.Clean(resolved), nil
}

func (s *Store) ensureBaseLayout() error {
	directories := []string{
		s.temporaryDirectory(),
		filepath.Join(s.root, dataDirectoryName),
		filepath.Join(s.root, dataDirectoryName, algorithmDirectoryName),
		filepath.Join(s.root, descriptorDirectoryName),
		filepath.Join(s.root, descriptorDirectoryName, algorithmDirectoryName),
	}
	for _, directory := range directories {
		if err := s.ensureManagedDirectory(directory); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) temporaryDirectory() string {
	return filepath.Join(s.root, temporaryDirectoryName)
}

func (s *Store) createManagedTemp(prefix string) (*os.File, string, error) {
	if err := s.checkManagedDirectory(s.temporaryDirectory()); err != nil {
		return nil, "", err
	}
	for range 128 {
		var random [16]byte
		if _, err := rand.Read(random[:]); err != nil {
			return nil, "", fmt.Errorf("generate CAS temporary name: %w", err)
		}
		name := filepath.Join(temporaryDirectoryName, prefix+hex.EncodeToString(random[:]))
		file, err := s.fs.OpenFile(name, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
		if errors.Is(err, os.ErrExist) {
			continue
		}
		if err != nil {
			return nil, "", err
		}
		if err := file.Chmod(0o600); err != nil {
			_ = file.Close()
			_ = s.fs.Remove(name)
			return nil, "", err
		}
		return file, name, nil
	}
	return nil, "", errors.New("cas: exhausted private temporary name attempts")
}

func (s *Store) objectPaths(objectDigest digest.Digest) (string, string, error) {
	if err := validateDigest(objectDigest); err != nil {
		return "", "", err
	}
	hex := objectDigest.Encoded()
	if len(hex) != 64 {
		return "", "", fmt.Errorf("cas: invalid sha256 digest length")
	}
	shard := hex[:2]
	name := hex[2:]
	dataPath := filepath.Join(s.root, dataDirectoryName, algorithmDirectoryName, shard, name)
	descriptorPath := filepath.Join(s.root, descriptorDirectoryName, algorithmDirectoryName, shard, name+".cbor")
	if err := s.requireWithinRoot(dataPath); err != nil {
		return "", "", err
	}
	if err := s.requireWithinRoot(descriptorPath); err != nil {
		return "", "", err
	}
	return dataPath, descriptorPath, nil
}

func (s *Store) ensureObjectDirectories(dataPath, descriptorPath string) error {
	if err := s.ensureManagedDirectory(filepath.Dir(dataPath)); err != nil {
		return err
	}
	return s.ensureManagedDirectory(filepath.Dir(descriptorPath))
}

func (s *Store) ensureManagedDirectory(path string) error {
	if err := s.requireWithinRoot(path); err != nil {
		return err
	}
	parent := filepath.Dir(path)
	if path != s.root {
		if err := s.checkManagedDirectory(parent); err != nil {
			return err
		}
	}
	name, err := s.managedName(path)
	if err != nil {
		return err
	}
	created := false
	if err := s.fs.Mkdir(name, 0o700); err != nil {
		if !errors.Is(err, os.ErrExist) {
			return fmt.Errorf("create CAS directory %q: %w", path, err)
		}
	} else {
		created = true
	}
	if err := s.checkManagedDirectory(path); err != nil {
		return err
	}
	if err := s.protectManagedPath(path, true); err != nil {
		return fmt.Errorf("protect CAS directory %q: %w", path, err)
	}
	if created {
		if err := s.syncManagedDirectory(parent); err != nil {
			return fmt.Errorf("sync parent of CAS directory %q: %w", path, err)
		}
		if err := s.syncManagedDirectory(path); err != nil {
			return fmt.Errorf("sync new CAS directory %q: %w", path, err)
		}
	}
	return nil
}

func (s *Store) requireWithinRoot(path string) error {
	clean := filepath.Clean(path)
	relative, err := filepath.Rel(s.root, clean)
	if err != nil {
		return fmt.Errorf("%w: resolve managed path: %v", ErrUnsafePath, err)
	}
	if relative == ".." || filepath.IsAbs(relative) || strings.HasPrefix(relative, ".."+string(os.PathSeparator)) {
		return fmt.Errorf("%w: %q escapes CAS root", ErrUnsafePath, path)
	}
	return nil
}

func (s *Store) managedName(path string) (string, error) {
	if err := s.requireWithinRoot(path); err != nil {
		return "", err
	}
	name, err := filepath.Rel(s.root, filepath.Clean(path))
	if err != nil {
		return "", fmt.Errorf("%w: resolve managed name: %v", ErrUnsafePath, err)
	}
	if filepath.IsAbs(name) || name == ".." || strings.HasPrefix(name, ".."+string(os.PathSeparator)) {
		return "", fmt.Errorf("%w: %q escapes CAS root", ErrUnsafePath, path)
	}
	return name, nil
}

func (s *Store) syncManagedDirectory(path string) error {
	name, err := s.managedName(path)
	if err != nil {
		return err
	}
	directory, err := s.fs.Open(name)
	if err != nil {
		return err
	}
	defer func() { _ = directory.Close() }()
	info, err := directory.Stat()
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return fmt.Errorf("%w: managed directory %q became a non-directory", ErrUnsafePath, path)
	}
	return syncOpenedDirectory(directory)
}

func (s *Store) protectManagedPath(path string, directory bool) error {
	name, err := s.managedName(path)
	if err != nil {
		return err
	}
	return protectManagedRootPath(s.fs, name, path, directory)
}

func (s *Store) checkManagedDirectory(path string) error {
	if err := s.requireWithinRoot(path); err != nil {
		return err
	}
	relative, err := filepath.Rel(s.root, path)
	if err != nil {
		return fmt.Errorf("%w: resolve directory chain: %v", ErrUnsafePath, err)
	}
	current := "."
	if err := s.checkRealDirectory(current, s.root); err != nil {
		return err
	}
	if relative == "." {
		return nil
	}
	for _, component := range strings.Split(relative, string(os.PathSeparator)) {
		current = filepath.Join(current, component)
		if err := s.checkRealDirectory(current, filepath.Join(s.root, current)); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) checkRealDirectory(name, displayPath string) error {
	info, err := s.fs.Lstat(name)
	if err != nil {
		return fmt.Errorf("inspect CAS directory %q: %w", displayPath, err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("%w: managed directory %q is a symlink or non-directory", ErrUnsafePath, displayPath)
	}
	return nil
}

func (s *Store) openManagedRegular(path string) (*os.File, os.FileInfo, error) {
	if err := s.requireWithinRoot(path); err != nil {
		return nil, nil, err
	}
	if err := s.checkManagedDirectory(filepath.Dir(path)); err != nil {
		return nil, nil, err
	}
	name, err := s.managedName(path)
	if err != nil {
		return nil, nil, err
	}
	info, err := s.fs.Lstat(name)
	if err != nil {
		return nil, nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, nil, fmt.Errorf("%w: managed file %q is a symlink or non-regular file", ErrUnsafePath, path)
	}
	file, err := s.fs.Open(name)
	if err != nil {
		return nil, nil, err
	}
	openedInfo, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, nil, fmt.Errorf("stat opened CAS file %q: %w", path, err)
	}
	if !openedInfo.Mode().IsRegular() {
		_ = file.Close()
		return nil, nil, fmt.Errorf("%w: opened file %q is non-regular", ErrUnsafePath, path)
	}
	if !os.SameFile(info, openedInfo) {
		_ = file.Close()
		return nil, nil, fmt.Errorf("%w: managed file %q changed while opening", ErrUnsafePath, path)
	}
	if err := rejectOpenedPlatformSpecial(file, path); err != nil {
		_ = file.Close()
		return nil, nil, err
	}
	return file, openedInfo, nil
}

func (s *Store) loadDescriptor(ctx context.Context, objectDigest digest.Digest) (artifact.Descriptor, bool, error) {
	_, descriptorPath, err := s.objectPaths(objectDigest)
	if err != nil {
		return artifact.Descriptor{}, false, err
	}
	file, info, err := s.openManagedRegular(descriptorPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return artifact.Descriptor{}, false, nil
		}
		return artifact.Descriptor{}, false, err
	}
	defer func() { _ = file.Close() }()
	if info.Size() <= 0 || info.Size() > maxDescriptorBytes {
		return artifact.Descriptor{}, false, fmt.Errorf("%w: descriptor sidecar has invalid size %d", ErrCorrupt, info.Size())
	}
	limited := io.LimitReader(&contextReader{ctx: ctx, source: file}, maxDescriptorBytes+1)
	encoded, err := io.ReadAll(limited)
	if err != nil {
		return artifact.Descriptor{}, false, fmt.Errorf("read descriptor sidecar: %w", err)
	}
	if int64(len(encoded)) != info.Size() || len(encoded) > maxDescriptorBytes {
		return artifact.Descriptor{}, false, fmt.Errorf("%w: descriptor sidecar changed while being read", ErrCorrupt)
	}
	descriptor, err := decodeDescriptor(encoded)
	if err != nil {
		return artifact.Descriptor{}, false, err
	}
	if descriptor.Digest != objectDigest {
		return artifact.Descriptor{}, false, fmt.Errorf("%w: descriptor records digest %s at path for %s", ErrCorrupt, descriptor.Digest, objectDigest)
	}
	return descriptor, true, nil
}
