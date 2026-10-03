package storage

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"sort"
	"strings"
	"time"
	"uuid"
)

type Local struct{ Dir string }

func (s *Local) Capabilities() Capabilities { return Capabilities{AtomicUpdates: true} }

func (s *Local) withLock(ctx context.Context, fn func(*os.Root) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := os.MkdirAll(s.Dir, 0o700); err != nil {
		return err
	}
	r, err := os.OpenRoot(s.Dir)
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

func readLocal(r *os.Root, key string) (Object, Version, error) {
	name := key + ".json"
	if err := rejectSymlink(r, name); err != nil {
		return Object{}, "", err
	}
	f, err := r.Open(name)
	if errors.Is(err, fs.ErrNotExist) {
		return Object{}, "", ErrNotFound
	}
	if err != nil {
		return Object{}, "", err
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(io.LimitReader(f, MaxEnvelopeBytes+1))
	if err != nil {
		return Object{}, "", err
	}
	o, err := Decode(b)
	return o, Version(fmt.Sprintf("sha256:%x", sha256.Sum256(b))), err
}

func (s *Local) Get(ctx context.Context, key string) (o Object, v Version, err error) {
	if err = ValidateKey(key); err != nil {
		return
	}
	err = s.withLock(ctx, func(r *os.Root) error { o, v, err = readLocal(r, key); return err })
	return
}

func (s *Local) Put(ctx context.Context, key string, o Object, expected Version) error {
	if err := ValidateKey(key); err != nil {
		return err
	}
	b, err := Encode(o)
	if err != nil {
		return err
	}
	return s.withLock(ctx, func(r *os.Root) error {
		_, current, err := readLocal(r, key)
		if err != nil && !errors.Is(err, ErrNotFound) {
			return err
		}
		if current != expected {
			return ErrConflict
		}
		name := ".pending-" + uuid.NewV4().String()
		f, err := r.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
		if err != nil {
			return err
		}
		defer func() { _ = f.Close(); _ = r.Remove(name) }()
		if _, err := f.Write(b); err != nil {
			return err
		}
		if err := f.Sync(); err != nil {
			return err
		}
		if err := f.Close(); err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		return r.Rename(name, key+".json")
	})
}

func (s *Local) List(ctx context.Context, prefix string) (keys []string, err error) {
	err = s.withLock(ctx, func(r *os.Root) error {
		f, err := r.Open(".")
		if err != nil {
			return err
		}
		defer func() { _ = f.Close() }()
		entries, err := f.ReadDir(-1)
		if err != nil {
			return err
		}
		for _, entry := range entries {
			if !strings.HasSuffix(entry.Name(), ".json") {
				continue
			}
			key := strings.TrimSuffix(entry.Name(), ".json")
			if !strings.HasPrefix(key, prefix) {
				continue
			}
			if err := ValidateKey(key); err != nil {
				return err
			}
			if err := rejectSymlink(r, entry.Name()); err != nil {
				return err
			}
			keys = append(keys, key)
		}
		sort.Strings(keys)
		return ctx.Err()
	})
	return
}
