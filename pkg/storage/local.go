package storage

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"sort"
	"strings"

	"github.com/opencontainers/go-digest"
	"uuid"
)

type local struct{ dir string }

const revisionDir = "revisions"

// NewLocal stores each revision as one file under dir/revisions.
func NewLocal(dir string) Store { return local{dir} }

func (s local) openRoot() (*os.Root, error) {
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return nil, err
	}
	return os.OpenRoot(s.dir)
}

func (s local) Capabilities() Capabilities { return Capabilities{PhysicalDelete: true} }

func rejectSymlink(r *os.Root, name string) error {
	info, err := r.Lstat(name)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("storage entry %s is not a regular file", name)
	}
	return nil
}

// syncSubdir syncs a directory below r, where renames into it were just made.
func syncSubdir(r *os.Root, dir string) error {
	sub, err := r.OpenRoot(dir)
	if err != nil {
		return err
	}
	defer func() { _ = sub.Close() }()
	return syncDirectory(sub)
}

func readLocal(r *os.Root, path string) ([]byte, error) {
	if err := rejectSymlink(r, path); err != nil {
		return nil, err
	}
	f, err := r.Open(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, maxFrameBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxFrameBytes {
		return nil, ErrTooLarge
	}
	return data, nil
}

// openLocal opens a stored object for ranged reads.
func openLocal(r *os.Root, path string) (*os.File, int64, error) {
	if err := rejectSymlink(r, path); err != nil {
		return nil, 0, err
	}
	f, err := r.Open(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, 0, ErrNotFound
	}
	if err != nil {
		return nil, 0, err
	}
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, 0, err
	}
	if info.Size() > maxFrameBytes {
		_ = f.Close()
		return nil, 0, ErrTooLarge
	}
	return f, info.Size(), nil
}

func (s local) Publish(ctx context.Context, o Object) error {
	if err := ValidateObject(o); err != nil {
		return err
	}
	name, err := Name(o.Kind, o.Scope, o.Rev)
	if err != nil {
		return err
	}
	data := frame(o)
	root, err := s.openRoot()
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()
	if err := root.MkdirAll(revisionDir, 0o700); err != nil {
		return err
	}
	path := revisionDir + "/" + name
	if existing, err := readLocal(root, path); err == nil {
		if bytes.Equal(existing, data) {
			return nil
		}
		return fmt.Errorf("%w: %s already holds different content", ErrCorrupt, name)
	} else if !errors.Is(err, ErrNotFound) {
		return err
	}
	pending := ".pending-" + uuid.NewV4().String()
	if err := root.WriteFile(pending, data, 0o600); err != nil {
		return err
	}
	defer func() { _ = root.Remove(pending) }()
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := commitLocalFile(root, pending, path, func(r *os.Root) error { return syncSubdir(r, revisionDir) }); err != nil {
		return err
	}
	f, size, err := openLocal(root, path)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	if size != int64(len(data)) {
		return fmt.Errorf("%w: %s has the wrong size after publishing", ErrCorrupt, name)
	}
	_, _, err = readHead(f, size, o.Rev)
	return err
}

func (s local) FetchHead(ctx context.Context, kind Kind, scope string, rev digest.Digest) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	name, err := Name(kind, scope, rev)
	if err != nil {
		return nil, err
	}
	root, err := s.openRoot()
	if err != nil {
		return nil, err
	}
	defer func() { _ = root.Close() }()
	f, size, err := openLocal(root, revisionDir+"/"+name)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	head, _, err := readHead(f, size, rev)
	return head, err
}

// OpenBlob streams one blob. The file stays open until the reader is closed, and
// reads only that blob's range.
func (s local) OpenBlob(ctx context.Context, kind Kind, scope string, rev digest.Digest, index int) (io.ReadCloser, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	name, err := Name(kind, scope, rev)
	if err != nil {
		return nil, err
	}
	root, err := s.openRoot()
	if err != nil {
		return nil, err
	}
	defer func() { _ = root.Close() }()
	f, size, err := openLocal(root, revisionDir+"/"+name)
	if err != nil {
		return nil, err
	}
	_, layout, err := readHead(f, size, rev)
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	section, err := blobSection(f, layout, index)
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	return struct {
		io.Reader
		io.Closer
	}{section, f}, nil
}

func (s local) Discover(ctx context.Context, kind Kind, scope string) ([]digest.Digest, error) {
	prefix, err := namePrefix(kind, scope)
	if err != nil {
		return nil, err
	}
	root, err := s.openRoot()
	if err != nil {
		return nil, err
	}
	defer func() { _ = root.Close() }()
	f, err := root.Open(revisionDir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, ctx.Err()
	}
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	entries, err := f.ReadDir(-1)
	if err != nil {
		return nil, err
	}
	var revs []digest.Digest
	for _, entry := range entries {
		if rev, ok := revFromName(prefix, entry.Name()); ok {
			revs = append(revs, rev)
		}
	}
	sort.Slice(revs, func(i, j int) bool { return strings.Compare(string(revs[i]), string(revs[j])) < 0 })
	return revs, ctx.Err()
}

func (s local) Delete(ctx context.Context, kind Kind, scope string, rev digest.Digest) error {
	name, err := Name(kind, scope, rev)
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	root, err := s.openRoot()
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()
	if err := root.Remove(revisionDir + "/" + name); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return ErrNotFound
		}
		return err
	}
	return nil
}

func commitLocalFile(r *os.Root, pending, name string, syncDir func(*os.Root) error) error {
	if err := r.Rename(pending, name); err != nil {
		return err
	}
	if err := syncDir(r); err != nil {
		return fmt.Errorf("syncing storage directory after replacement (update is already visible): %w", err)
	}
	return nil
}
