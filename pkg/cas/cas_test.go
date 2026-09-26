package cas

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"

	"github.com/enbu-net/enbu/pkg/artifact"
	"github.com/opencontainers/go-digest"
)

const testMediaType = "application/octet-stream"

func TestStoreIngestOpenAndHas(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	data := bytes.Repeat([]byte("streamed-cas-object\n"), 300_000)
	source := &boundedReadTracker{source: bytes.NewReader(data), maximum: copyBufferSize}

	descriptor, err := store.Ingest(context.Background(), testMediaType, source)
	if err != nil {
		t.Fatalf("Ingest() error = %v", err)
	}
	want := artifact.Descriptor{MediaType: testMediaType, Digest: digest.FromBytes(data), Size: int64(len(data))}
	if descriptor != want {
		t.Fatalf("descriptor = %#v, want %#v", descriptor, want)
	}
	if source.largest > copyBufferSize {
		t.Fatalf("largest source read = %d, want <= %d", source.largest, copyBufferSize)
	}

	has, err := store.Has(context.Background(), descriptor.Digest)
	if err != nil || !has {
		t.Fatalf("Has() = %v, %v", has, err)
	}
	reader, opened, err := store.Open(context.Background(), descriptor.Digest)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	if opened != descriptor {
		t.Fatalf("opened descriptor = %#v, want %#v", opened, descriptor)
	}
	got, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("ReadAll() error = %v", err)
	}
	if err := reader.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Fatal("opened bytes differ from ingested bytes")
	}
}

func TestStoreEmptyObject(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	descriptor, err := store.Ingest(context.Background(), testMediaType, bytes.NewReader(nil))
	if err != nil {
		t.Fatalf("Ingest() error = %v", err)
	}
	reader, _, err := store.Open(context.Background(), descriptor.Digest)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	got, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("ReadAll() error = %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("read %d bytes from empty object", len(got))
	}
}

func TestStoreConcurrentSameObject(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	data := bytes.Repeat([]byte("same immutable object"), 10_000)
	want := artifact.Descriptor{MediaType: "text/plain", Digest: digest.FromBytes(data), Size: int64(len(data))}

	const workers = 32
	descriptors := make(chan artifact.Descriptor, workers)
	errorsChannel := make(chan error, workers)
	var group sync.WaitGroup
	for range workers {
		group.Add(1)
		go func() {
			defer group.Done()
			descriptor, err := store.Ingest(context.Background(), want.MediaType, bytes.NewReader(data))
			if err != nil {
				errorsChannel <- err
				return
			}
			descriptors <- descriptor
		}()
	}
	group.Wait()
	close(errorsChannel)
	close(descriptors)
	for err := range errorsChannel {
		t.Errorf("concurrent Ingest() error = %v", err)
	}
	for descriptor := range descriptors {
		if descriptor != want {
			t.Errorf("descriptor = %#v, want %#v", descriptor, want)
		}
	}
	if t.Failed() {
		return
	}
	has, err := store.Has(context.Background(), want.Digest)
	if err != nil || !has {
		t.Fatalf("Has() = %v, %v", has, err)
	}
}

func TestStoreRejectsMediaTypeConflictForSameDigest(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	data := []byte("one digest has one descriptor")
	first, err := store.Ingest(context.Background(), "text/plain", bytes.NewReader(data))
	if err != nil {
		t.Fatalf("first Ingest() error = %v", err)
	}
	_, err = store.Ingest(context.Background(), testMediaType, bytes.NewReader(data))
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("second Ingest() error = %v, want ErrConflict", err)
	}
	reader, descriptor, err := store.Open(context.Background(), first.Digest)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer func() {
		if err := reader.Close(); err != nil {
			t.Errorf("Close() error = %v", err)
		}
	}()
	if descriptor.MediaType != "text/plain" {
		t.Fatalf("media type = %q, want text/plain", descriptor.MediaType)
	}
}

func TestStoreDescriptorIsVisibilityPoint(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	data := []byte("orphan data from an interrupted publication")
	descriptor := artifact.Descriptor{MediaType: testMediaType, Digest: digest.FromBytes(data), Size: int64(len(data))}
	dataPath, _, err := store.objectPaths(descriptor.Digest)
	if err != nil {
		t.Fatal(err)
	}
	_, descriptorPath, _ := store.objectPaths(descriptor.Digest)
	if err := store.ensureObjectDirectories(dataPath, descriptorPath); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dataPath, data, 0o400); err != nil {
		t.Fatal(err)
	}

	has, err := store.Has(context.Background(), descriptor.Digest)
	if err != nil || has {
		t.Fatalf("Has(orphan data) = %v, %v", has, err)
	}
	if _, _, err := store.Open(context.Background(), descriptor.Digest); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Open(orphan data) error = %v, want ErrNotFound", err)
	}

	recovered, err := store.Ingest(context.Background(), testMediaType, bytes.NewReader(data))
	if err != nil {
		t.Fatalf("recovering Ingest() error = %v", err)
	}
	if recovered != descriptor {
		t.Fatalf("recovered descriptor = %#v, want %#v", recovered, descriptor)
	}
}

func TestStoreNeverReplacesCorruptOrphanData(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	data := []byte("expected immutable orphan")
	descriptor := artifact.Descriptor{MediaType: testMediaType, Digest: digest.FromBytes(data), Size: int64(len(data))}
	dataPath, descriptorPath, err := store.objectPaths(descriptor.Digest)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.ensureObjectDirectories(dataPath, descriptorPath); err != nil {
		t.Fatal(err)
	}
	corrupt := bytes.Repeat([]byte{'z'}, len(data))
	if err := os.WriteFile(dataPath, corrupt, 0o400); err != nil {
		t.Fatal(err)
	}

	if _, err := store.Ingest(context.Background(), testMediaType, bytes.NewReader(data)); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("Ingest() error = %v, want ErrCorrupt", err)
	}
	got, err := os.ReadFile(dataPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, corrupt) {
		t.Fatal("Ingest replaced existing corrupt data")
	}
	has, err := store.Has(context.Background(), descriptor.Digest)
	if err != nil || has {
		t.Fatalf("Has(corrupt orphan) = %v, %v", has, err)
	}
}

func TestStoreIgnoresTemporaryOrphans(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	data := []byte("not published")
	if err := os.WriteFile(filepath.Join(store.temporaryDirectory(), "orphan"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	has, err := store.Has(context.Background(), digest.FromBytes(data))
	if err != nil || has {
		t.Fatalf("Has(temp orphan) = %v, %v", has, err)
	}
}

func TestStoreReportsDescriptorWithoutDataAsCorruption(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	data := []byte("missing object data")
	descriptor := artifact.Descriptor{MediaType: testMediaType, Digest: digest.FromBytes(data), Size: int64(len(data))}
	dataPath, descriptorPath, err := store.objectPaths(descriptor.Digest)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.ensureObjectDirectories(dataPath, descriptorPath); err != nil {
		t.Fatal(err)
	}
	writeDescriptorForTest(t, descriptorPath, descriptor)

	if _, _, err := store.Open(context.Background(), descriptor.Digest); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("Open() error = %v, want ErrCorrupt", err)
	}
	if has, err := store.Has(context.Background(), descriptor.Digest); has || !errors.Is(err, ErrCorrupt) {
		t.Fatalf("Has() = %v, %v, want false and ErrCorrupt", has, err)
	}
}

func TestStoreDoesNotExposePartialIngest(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	first := []byte("first part")
	second := []byte("second part")
	all := append(append([]byte(nil), first...), second...)
	source := &stagedReader{first: first, second: second, started: make(chan struct{}), release: make(chan struct{})}
	result := make(chan error, 1)
	go func() {
		_, err := store.Ingest(context.Background(), testMediaType, source)
		result <- err
	}()
	<-source.started
	has, err := store.Has(context.Background(), digest.FromBytes(all))
	if err != nil || has {
		t.Fatalf("Has(partial ingest) = %v, %v", has, err)
	}
	close(source.release)
	if err := <-result; err != nil {
		t.Fatalf("Ingest() error = %v", err)
	}
}

func TestStoreCancellationLeavesNoVisibleObject(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	data := []byte("cancel during source read")
	ctx, cancel := context.WithCancel(context.Background())
	source := &cancelingReader{data: data, cancel: cancel}
	_, err := store.Ingest(ctx, testMediaType, source)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Ingest() error = %v, want context.Canceled", err)
	}
	has, err := store.Has(context.Background(), digest.FromBytes(data))
	if err != nil || has {
		t.Fatalf("Has(canceled object) = %v, %v", has, err)
	}
	assertTemporaryDirectoryEmpty(t, store)
}

func TestStoreSourceErrorLeavesNoVisibleObject(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	sourceErr := errors.New("source failed")
	data := []byte("partial source")
	_, err := store.Ingest(context.Background(), testMediaType, &failingReader{data: data, err: sourceErr})
	if !errors.Is(err, sourceErr) {
		t.Fatalf("Ingest() error = %v, want source error", err)
	}
	has, err := store.Has(context.Background(), digest.FromBytes(data))
	if err != nil || has {
		t.Fatalf("Has(failed object) = %v, %v", has, err)
	}
	assertTemporaryDirectoryEmpty(t, store)
}

func TestStoreInterruptedAfterDataPublishCanRecover(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	originalPublish := store.publish
	publicationFailure := errors.New("simulated descriptor publication failure")
	calls := 0
	store.publish = func(root *os.Root, source, destination string) (bool, error) {
		calls++
		if calls == 2 {
			return false, publicationFailure
		}
		return originalPublish(root, source, destination)
	}
	data := []byte("data survives before visibility point")
	_, err := store.Ingest(context.Background(), testMediaType, bytes.NewReader(data))
	if !errors.Is(err, publicationFailure) {
		t.Fatalf("Ingest() error = %v, want simulated failure", err)
	}
	has, err := store.Has(context.Background(), digest.FromBytes(data))
	if err != nil || has {
		t.Fatalf("Has(interrupted object) = %v, %v", has, err)
	}

	store.publish = originalPublish
	if _, err := store.Ingest(context.Background(), testMediaType, bytes.NewReader(data)); err != nil {
		t.Fatalf("recovering Ingest() error = %v", err)
	}
}

func TestStoreFailsClosedWithoutAtomicPublish(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	store.publish = func(*os.Root, string, string) (bool, error) {
		return false, ErrUnsupportedAtomicPublish
	}
	data := []byte("must remain invisible")
	_, err := store.Ingest(context.Background(), testMediaType, bytes.NewReader(data))
	if !errors.Is(err, ErrUnsupportedAtomicPublish) {
		t.Fatalf("Ingest() error = %v, want ErrUnsupportedAtomicPublish", err)
	}
	has, err := store.Has(context.Background(), digest.FromBytes(data))
	if err != nil || has {
		t.Fatalf("Has() = %v, %v", has, err)
	}
}

func TestStoreDetectsDataTamper(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	data := []byte("original immutable bytes")
	descriptor, err := store.Ingest(context.Background(), testMediaType, bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	dataPath, _, _ := store.objectPaths(descriptor.Digest)
	makeWritableForTest(t, dataPath)
	tampered := bytes.Repeat([]byte{'x'}, len(data))
	if err := os.WriteFile(dataPath, tampered, 0o400); err != nil {
		t.Fatal(err)
	}

	reader, _, err := store.Open(context.Background(), descriptor.Digest)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	_, err = io.ReadAll(reader)
	if !errors.Is(err, ErrCorrupt) {
		t.Fatalf("ReadAll() error = %v, want ErrCorrupt", err)
	}
	if has, err := store.Has(context.Background(), descriptor.Digest); has || !errors.Is(err, ErrCorrupt) {
		t.Fatalf("Has() = %v, %v, want false and ErrCorrupt", has, err)
	}
}

func TestStoreDetectsDescriptorTamper(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	descriptor, err := store.Ingest(context.Background(), testMediaType, bytes.NewReader([]byte("descriptor target")))
	if err != nil {
		t.Fatal(err)
	}
	_, descriptorPath, _ := store.objectPaths(descriptor.Digest)
	makeWritableForTest(t, descriptorPath)
	if err := os.WriteFile(descriptorPath, []byte("not canonical CBOR"), 0o400); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.Open(context.Background(), descriptor.Digest); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("Open() error = %v, want ErrCorrupt", err)
	}
}

func TestStoreDetectsDescriptorDigestSubstitution(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	descriptor, err := store.Ingest(context.Background(), testMediaType, bytes.NewReader([]byte("descriptor target")))
	if err != nil {
		t.Fatal(err)
	}
	_, descriptorPath, _ := store.objectPaths(descriptor.Digest)
	makeWritableForTest(t, descriptorPath)
	descriptor.Digest = digest.FromBytes([]byte("substituted"))
	writeDescriptorForTest(t, descriptorPath, descriptor)
	if _, _, err := store.Open(context.Background(), digest.FromBytes([]byte("descriptor target"))); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("Open() error = %v, want ErrCorrupt", err)
	}
}

func TestStoreRejectsSymlinkAndNonRegularManagedFiles(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	descriptor, err := store.Ingest(context.Background(), testMediaType, bytes.NewReader([]byte("symlink target")))
	if err != nil {
		t.Fatal(err)
	}
	dataPath, descriptorPath, _ := store.objectPaths(descriptor.Digest)
	makeWritableForTest(t, dataPath)
	if err := os.Remove(dataPath); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(target, []byte("symlink target"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, dataPath); err != nil {
		if runtime.GOOS == "windows" {
			t.Skipf("creating symlinks is unavailable: %v", err)
		}
		t.Fatal(err)
	}
	if _, _, err := store.Open(context.Background(), descriptor.Digest); !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("Open(symlink data) error = %v, want ErrUnsafePath", err)
	}

	makeWritableForTest(t, descriptorPath)
	if err := os.Remove(descriptorPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(descriptorPath, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.Open(context.Background(), descriptor.Digest); !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("Open(directory descriptor) error = %v, want ErrUnsafePath", err)
	}
}

func TestStoreRejectsSymlinkShardDirectory(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	data := []byte("object routed through shard")
	objectDigest := digest.FromBytes(data)
	dataPath, _, _ := store.objectPaths(objectDigest)
	shard := filepath.Dir(dataPath)
	target := t.TempDir()
	if err := os.Symlink(target, shard); err != nil {
		if runtime.GOOS == "windows" {
			t.Skipf("creating symlinks is unavailable: %v", err)
		}
		t.Fatal(err)
	}
	_, err := store.Ingest(context.Background(), testMediaType, bytes.NewReader(data))
	if !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("Ingest() error = %v, want ErrUnsafePath", err)
	}
}

func TestStoreValidatesDigestAndMediaType(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	invalidDigests := []digest.Digest{"", "sha256:../escape", digest.Digest("sha512:" + string(bytes.Repeat([]byte{'a'}, 128)))}
	for _, invalid := range invalidDigests {
		if _, _, err := store.Open(context.Background(), invalid); err == nil {
			t.Errorf("Open(%q) succeeded", invalid)
		}
	}
	for _, mediaType := range []string{"", "not a media type"} {
		if _, err := store.Ingest(context.Background(), mediaType, bytes.NewReader(nil)); err == nil {
			t.Errorf("Ingest(mediaType=%q) succeeded", mediaType)
		}
	}
}

func TestStoreHonorsCanceledReadAndHas(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	descriptor, err := store.Ingest(context.Background(), testMediaType, bytes.NewReader(bytes.Repeat([]byte("data"), 1000)))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := store.Open(ctx, descriptor.Digest); !errors.Is(err, context.Canceled) {
		t.Fatalf("Open() error = %v, want context.Canceled", err)
	}
	if has, err := store.Has(ctx, descriptor.Digest); has || !errors.Is(err, context.Canceled) {
		t.Fatalf("Has() = %v, %v, want false and context.Canceled", has, err)
	}
}

func TestNewRejectsSymlinkRoot(t *testing.T) {
	t.Parallel()
	parent := t.TempDir()
	target := filepath.Join(parent, "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(parent, "link")
	if err := os.Symlink(target, link); err != nil {
		if runtime.GOOS == "windows" {
			t.Skipf("creating symlinks is unavailable: %v", err)
		}
		t.Fatal(err)
	}
	if _, err := New(link); !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("New(symlink) error = %v, want ErrUnsafePath", err)
	}
}

func TestStoreZeroValueFailsClosed(t *testing.T) {
	t.Parallel()
	var store Store
	if _, err := store.Ingest(context.Background(), testMediaType, bytes.NewReader(nil)); err == nil {
		t.Fatal("zero-value Store.Ingest() succeeded")
	}
	if _, _, err := store.Open(context.Background(), digest.FromBytes(nil)); err == nil {
		t.Fatal("zero-value Store.Open() succeeded")
	}
	var nilStore *Store
	if _, _, err := nilStore.Open(context.Background(), digest.FromBytes(nil)); err == nil {
		t.Fatal("nil Store.Open() succeeded")
	}
}

func newTestStore(t *testing.T) *Store {
	t.Helper()
	store, err := New(filepath.Join(t.TempDir(), "cas"))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Errorf("Close() error = %v", err)
		}
	})
	return store
}

func writeDescriptorForTest(t *testing.T, path string, descriptor artifact.Descriptor) {
	t.Helper()
	encoded, err := encodeDescriptor(descriptor)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, encoded, 0o400); err != nil {
		t.Fatal(err)
	}
}

func makeWritableForTest(t *testing.T, path string) {
	t.Helper()
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
}

func assertTemporaryDirectoryEmpty(t *testing.T, store *Store) {
	t.Helper()
	entries, err := os.ReadDir(store.temporaryDirectory())
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("temporary directory contains %d orphan files", len(entries))
	}
}

type boundedReadTracker struct {
	source  io.Reader
	maximum int
	largest int
}

func (r *boundedReadTracker) Read(destination []byte) (int, error) {
	if len(destination) > r.maximum {
		return 0, fmt.Errorf("read buffer %d exceeds maximum %d", len(destination), r.maximum)
	}
	if len(destination) > r.largest {
		r.largest = len(destination)
	}
	return r.source.Read(destination)
}

type stagedReader struct {
	first   []byte
	second  []byte
	started chan struct{}
	release chan struct{}
	step    int
}

func (r *stagedReader) Read(destination []byte) (int, error) {
	switch r.step {
	case 0:
		r.step++
		close(r.started)
		return copy(destination, r.first), nil
	case 1:
		r.step++
		<-r.release
		return copy(destination, r.second), nil
	default:
		return 0, io.EOF
	}
}

type cancelingReader struct {
	data   []byte
	cancel context.CancelFunc
	done   bool
}

func (r *cancelingReader) Read(destination []byte) (int, error) {
	if r.done {
		return 0, io.EOF
	}
	r.done = true
	n := copy(destination, r.data)
	r.cancel()
	return n, nil
}

type failingReader struct {
	data []byte
	err  error
	done bool
}

func (r *failingReader) Read(destination []byte) (int, error) {
	if r.done {
		return 0, r.err
	}
	r.done = true
	return copy(destination, r.data), nil
}
