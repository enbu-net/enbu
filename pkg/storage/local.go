package storage

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"sort"
	"strings"
	"time"
	"uuid"

	"github.com/opencontainers/go-digest"
)

type local struct{ dir string }
type localBlobs struct{ local }
type localRefs struct{ local }

// NewLocal stores blobs under dir/blobs/sha256 and refs under dir/refs.
func NewLocal(dir string) *Store {
	l := local{dir}
	return &Store{Blobs: localBlobs{l}, Refs: localRefs{l}}
}

func (s local) openRoot() (*os.Root, error) {
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return nil, err
	}
	return os.OpenRoot(s.dir)
}

func (s local) withLock(ctx context.Context, fn func(*os.Root) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	r, err := s.openRoot()
	if err != nil {
		return err
	}
	defer func() { _ = r.Close() }()
	if err := rejectSymlink(r, ".enbu.lock"); err != nil {
		return err
	}
	f, err := r.OpenFile(".enbu.lock", os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	for {
		ok, err := tryLock(f)
		if err != nil {
			return err
		}
		if ok {
			break
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(10 * time.Millisecond):
		}
	}
	defer unlock(f)
	if err := ctx.Err(); err != nil {
		return err
	}
	return fn(r)
}

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

const blobDir = "blobs/sha256"

func blobPath(d digest.Digest) (string, error) {
	if err := ValidateDigest(d); err != nil {
		return "", err
	}
	return blobDir + "/" + d.Encoded(), nil
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

// stage writes the content of r to a pending file in the storage root.
func stage(ctx context.Context, root *os.Root, src io.Reader) (name string, d digest.Digest, err error) {
	name = ".pending-" + uuid.NewV4().String()
	f, err := root.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
	if err != nil {
		return "", "", err
	}
	defer func() {
		_ = f.Close()
		if err != nil {
			_ = root.Remove(name)
		}
	}()
	d, _, err = copyHashed(ctx, f, src)
	if err == nil {
		err = f.Sync()
	}
	return name, d, err
}

func (s localBlobs) Put(ctx context.Context, src io.Reader) (digest.Digest, error) {
	root, err := s.openRoot()
	if err != nil {
		return "", err
	}
	defer func() { _ = root.Close() }()
	if err := root.MkdirAll(blobDir, 0o700); err != nil {
		return "", err
	}
	pending, d, err := stage(ctx, root, src)
	if err != nil {
		return "", err
	}
	defer func() { _ = root.Remove(pending) }()
	path, err := blobPath(d)
	if err != nil {
		return "", err
	}
	if _, err := root.Lstat(path); err == nil {
		// Same digest, same content. Renaming over it would fail on Windows
		// while another process has the blob open.
		if err := rejectSymlink(root, path); err != nil {
			return "", err
		}
		return d, nil
	} else if !errors.Is(err, fs.ErrNotExist) {
		return "", err
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	return d, commitLocalFile(root, pending, path, func(r *os.Root) error { return syncSubdir(r, blobDir) })
}

func (s localBlobs) Open(ctx context.Context, d digest.Digest) (io.ReadCloser, error) {
	path, err := blobPath(d)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	root, err := s.openRoot()
	if err != nil {
		return nil, err
	}
	defer func() { _ = root.Close() }()
	if err := rejectSymlink(root, path); err != nil {
		return nil, err
	}
	f, err := root.Open(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return newVerifyReader(f, d), nil
}

func readLocalRef(r *os.Root, name string) (digest.Digest, Version, error) {
	path := "refs/" + name
	if err := rejectSymlink(r, path); err != nil {
		return "", "", err
	}
	b, err := r.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return "", "", ErrNotFound
	}
	if err != nil {
		return "", "", err
	}
	d, err := parseRef(b)
	return d, Version(d), err
}

func (s localRefs) Get(ctx context.Context, name string) (d digest.Digest, v Version, err error) {
	if err = ValidateKey(name); err != nil {
		return
	}
	err = s.withLock(ctx, func(r *os.Root) error { d, v, err = readLocalRef(r, name); return err })
	return
}

// Put atomically replaces a ref. On Unix it also syncs the containing
// directory. If that sync fails, Put returns an error even though the replacement
// is already visible; callers must reload its version before retrying.
func (s localRefs) Put(ctx context.Context, name string, target digest.Digest, expected Version) error {
	if err := ValidateKey(name); err != nil {
		return err
	}
	if err := ValidateDigest(target); err != nil {
		return err
	}
	return s.withLock(ctx, func(r *os.Root) error {
		if err := r.MkdirAll("refs", 0o700); err != nil {
			return err
		}
		_, current, err := readLocalRef(r, name)
		if err != nil && !errors.Is(err, ErrNotFound) {
			return err
		}
		if current != expected {
			return ErrConflict
		}
		pending := ".pending-" + uuid.NewV4().String()
		if err := r.WriteFile(pending, []byte(target), 0o600); err != nil {
			return err
		}
		defer func() { _ = r.Remove(pending) }()
		if err := ctx.Err(); err != nil {
			return err
		}
		return commitLocalFile(r, pending, "refs/"+name, func(r *os.Root) error { return syncSubdir(r, "refs") })
	})
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

func (s localRefs) List(ctx context.Context, prefix string) (keys []string, err error) {
	err = s.withLock(ctx, func(r *os.Root) error {
		f, err := r.Open("refs")
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		defer func() { _ = f.Close() }()
		entries, err := f.ReadDir(-1)
		if err != nil {
			return err
		}
		for _, entry := range entries {
			if !strings.HasPrefix(entry.Name(), prefix) {
				continue
			}
			if err := ValidateKey(entry.Name()); err != nil {
				return err
			}
			if err := rejectSymlink(r, "refs/"+entry.Name()); err != nil {
				return err
			}
			keys = append(keys, entry.Name())
		}
		sort.Strings(keys)
		return ctx.Err()
	})
	return
}
