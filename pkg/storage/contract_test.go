package storage_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/enbu-net/enbu/pkg/storage"
	"github.com/enbu-net/enbu/pkg/storage/storagetest"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/yashikota/minis3"
	"oras.land/oras-go/v2/registry/remote/auth"
)

func TestMemoryContract(t *testing.T) { storagetest.Contract(t, storagetest.NewMemory()) }

func TestLocalContract(t *testing.T) {
	st := storage.NewLocal(filepath.Join(t.TempDir(), "store"))
	storagetest.Contract(t, st)
}

func minis3Client(t *testing.T) *minio.Client {
	t.Helper()
	server, err := minis3.Run()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close() })
	client, err := minio.New(server.Addr(), &minio.Options{Region: "us-east-1", Creds: credentials.NewStaticV4("test", "test", ""), Secure: false, BucketLookup: minio.BucketLookupPath})
	if err != nil {
		t.Fatal(err)
	}
	if err := client.MakeBucket(context.Background(), "enbu-test", minio.MakeBucketOptions{Region: "us-east-1"}); err != nil {
		t.Fatal(err)
	}
	return client
}

func TestS3Contract(t *testing.T) {
	client := minis3Client(t)
	storagetest.Contract(t, storage.NewS3(client, "enbu-test", "workspace"))
}

func TestS3BucketRootContract(t *testing.T) {
	client := minis3Client(t)
	storagetest.Contract(t, storage.NewS3(client, "enbu-test", ""))
}

func TestS3PrefixesAreIsolated(t *testing.T) {
	client := minis3Client(t)
	ctx := context.Background()
	a, b := storage.NewS3(client, "enbu-test", "a"), storage.NewS3(client, "enbu-test", "b")
	o := storagetest.Object(storage.KindControl, "", "signed", "")
	if err := a.Publish(ctx, o); err != nil {
		t.Fatal(err)
	}
	if revs, err := b.Discover(ctx, storage.KindControl, ""); err != nil || len(revs) != 0 {
		t.Fatalf("other prefix sees %v %v", revs, err)
	}
}

func TestS3DiscoverPaginates(t *testing.T) {
	client := minis3Client(t)
	ctx := context.Background()
	st := storage.NewS3(client, "enbu-test", "ws")
	const n = 1003
	for i := range n {
		if err := st.Publish(ctx, storagetest.Object(storage.KindRequest, "", fmt.Sprintf("request-%d", i), "")); err != nil {
			t.Fatal(err)
		}
	}
	revs, err := st.Discover(ctx, storage.KindRequest, "")
	if err != nil || len(revs) != n {
		t.Fatalf("discover = %d %v", len(revs), err)
	}
}

func TestS3FetchRejectsTamperedAndMalformedObjects(t *testing.T) {
	client := minis3Client(t)
	ctx := context.Background()
	st := storage.NewS3(client, "enbu-test", "ws")
	o := storagetest.Object(storage.KindControl, "", "signed-control", "")
	if err := st.Publish(ctx, o); err != nil {
		t.Fatal(err)
	}
	name, _ := storage.Name(o.Kind, o.Scope, o.Rev)
	key := "ws/revisions/" + name
	for _, body := range []string{"", "garbage", "\x0dsigned-controlX"} {
		if _, err := client.PutObject(ctx, "enbu-test", key, strings.NewReader(body), int64(len(body)), minio.PutObjectOptions{}); err != nil {
			t.Fatal(err)
		}
		if _, err := st.Fetch(ctx, o.Kind, o.Scope, o.Rev); !errors.Is(err, storage.ErrCorrupt) {
			t.Fatalf("body %q: %v", body, err)
		}
	}
	if err := st.Publish(ctx, o); !errors.Is(err, storage.ErrCorrupt) {
		t.Fatalf("publish over a different object: %v", err)
	}
}

func TestNewS3ClientCredentials(t *testing.T) {
	for _, source := range []string{"environment", "profile"} {
		t.Run(source, func(t *testing.T) {
			for _, k := range []string{"AWS_ACCESS_KEY_ID", "AWS_ACCESS_KEY", "AWS_SECRET_ACCESS_KEY", "AWS_SECRET_KEY", "AWS_SESSION_TOKEN"} {
				t.Setenv(k, "")
			}
			t.Setenv("AWS_REGION", "test-region")
			t.Setenv("AWS_PROFILE", "enbu-test")
			cfg := filepath.Join(t.TempDir(), "config")
			creds := filepath.Join(t.TempDir(), "credentials")
			t.Setenv("AWS_CONFIG_FILE", cfg)
			t.Setenv("AWS_SHARED_CREDENTIALS_FILE", creds)
			if err := os.WriteFile(cfg, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			if source == "environment" {
				t.Setenv("AWS_ACCESS_KEY_ID", "test-key")
				t.Setenv("AWS_SECRET_ACCESS_KEY", "test-secret")
				t.Setenv("AWS_SESSION_TOKEN", "test-token")
			} else if err := os.WriteFile(creds, []byte("[enbu-test]\naws_access_key_id=test-key\naws_secret_access_key=test-secret\naws_session_token=test-token\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			o := storagetest.Object(storage.KindControl, "", "signed", "")
			name, _ := storage.Name(o.Kind, o.Scope, o.Rev)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet || r.URL.Path != "/enbu-test/workspace/revisions/"+name {
					t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
				}
				if !strings.Contains(r.Header.Get("Authorization"), "Credential=test-key/") ||
					!strings.Contains(r.Header.Get("Authorization"), "/test-region/s3/aws4_request") ||
					r.Header.Get("X-Amz-Security-Token") != "test-token" {
					t.Error("request did not use the selected credentials and region")
				}
				w.Header().Set("Content-Type", "application/xml")
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write([]byte(`<Error><Code>NoSuchKey</Code></Error>`))
			}))
			t.Cleanup(server.Close)
			client, err := storage.NewS3Client(server.URL, "", true)
			if err != nil {
				t.Fatal(err)
			}
			_, err = storage.NewS3(client, "enbu-test", "workspace").Fetch(context.Background(), o.Kind, o.Scope, o.Rev)
			if !errors.Is(err, storage.ErrNotFound) {
				t.Fatalf("authenticated read: %v", err)
			}
		})
	}
}

func TestNewS3ClientEndpointValidation(t *testing.T) {
	for _, endpoint := range []string{"relative", "ftp://example.com", "https://user:password@example.com", "https://example.com/path", "https://example.com?query=1", "https://example.com#fragment"} {
		if _, err := storage.NewS3Client(endpoint, "us-east-1", false); err == nil {
			t.Fatalf("accepted endpoint %q", endpoint)
		}
	}
	client, err := storage.NewS3Client("", "us-east-1", false)
	if err != nil {
		t.Fatal(err)
	}
	if got := client.EndpointURL().String(); got != "https://s3.amazonaws.com" {
		t.Fatalf("default endpoint=%q", got)
	}
}

// fakeRegistry implements the subset of the distribution API that the OCI store uses.
type fakeRegistry struct {
	mu        sync.Mutex
	blobs     map[string][]byte
	manifests map[string][]byte // by tag and by digest
	puts      int
	blobPuts  int
	// unknownWhenEmpty answers tags/list of a repository nothing was pushed to
	// with 404 NAME_UNKNOWN, as zot and GHCR do.
	unknownWhenEmpty bool
}

func newFakeRegistry(t *testing.T) (*fakeRegistry, storage.Store) {
	t.Helper()
	r := &fakeRegistry{blobs: map[string][]byte{}, manifests: map[string][]byte{}}
	server := httptest.NewServer(r)
	t.Cleanup(server.Close)
	s, err := storage.NewOCI(strings.TrimPrefix(server.URL, "http://")+"/enbu", func(context.Context, string) (auth.Credential, error) {
		return auth.EmptyCredential, nil
	}, true)
	if err != nil {
		t.Fatal(err)
	}
	return r, s
}

func (r *fakeRegistry) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	r.mu.Lock()
	defer r.mu.Unlock()
	path := strings.TrimPrefix(req.URL.Path, "/v2/enbu/")
	serve := func(data []byte, ok bool, mediaType, dgst string) {
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", mediaType)
		w.Header().Set("Content-Length", strconv.Itoa(len(data)))
		w.Header().Set("Docker-Content-Digest", dgst)
		if req.Method == http.MethodGet {
			_, _ = w.Write(data)
		}
	}
	switch {
	case path == "blobs/uploads/" && req.Method == http.MethodPost:
		w.Header().Set("Location", "/v2/enbu/blobs/uploads/session")
		w.WriteHeader(http.StatusAccepted)
	case strings.HasPrefix(path, "blobs/uploads/") && req.Method == http.MethodPut:
		b, _ := io.ReadAll(req.Body)
		if digest.FromBytes(b).String() != req.URL.Query().Get("digest") {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		r.blobPuts++
		r.blobs[req.URL.Query().Get("digest")] = b
		w.WriteHeader(http.StatusCreated)
	case strings.HasPrefix(path, "blobs/"):
		key := strings.TrimPrefix(path, "blobs/")
		b, ok := r.blobs[key]
		serve(b, ok, "application/octet-stream", key) // a registry reports the address, not a recomputed hash
	case strings.HasPrefix(path, "manifests/") && req.Method == http.MethodPut:
		b, _ := io.ReadAll(req.Body)
		var m ocispec.Manifest
		if err := json.Unmarshal(b, &m); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		for _, d := range append([]ocispec.Descriptor{m.Config}, m.Layers...) {
			if _, ok := r.blobs[d.Digest.String()]; !ok {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
		}
		r.puts++
		r.manifests[strings.TrimPrefix(path, "manifests/")] = b
		r.manifests[digest.FromBytes(b).String()] = b
		w.Header().Set("Docker-Content-Digest", digest.FromBytes(b).String())
		w.WriteHeader(http.StatusCreated)
	case strings.HasPrefix(path, "manifests/"):
		b, ok := r.manifests[strings.TrimPrefix(path, "manifests/")]
		serve(b, ok, ocispec.MediaTypeImageManifest, digest.FromBytes(b).String())
	case path == "tags/list" && r.unknownWhenEmpty && len(r.blobs) == 0:
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"errors":[{"code":"NAME_UNKNOWN","message":"repository name not known to registry"}]}`))
	case path == "tags/list":
		var tags []string
		for k := range r.manifests {
			if !strings.HasPrefix(k, "sha256:") {
				tags = append(tags, k)
			}
		}
		sort.Strings(tags)
		_ = json.NewEncoder(w).Encode(map[string]any{"name": "enbu", "tags": tags})
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func TestOCIContractAgainstFakeRegistry(t *testing.T) {
	_, s := newFakeRegistry(t)
	storagetest.Contract(t, s)
}

func TestOCIPublishesOneManifestWithBothLayers(t *testing.T) {
	r, s := newFakeRegistry(t)
	o := storagetest.Object(storage.KindState, storagetest.Scope("secrets/dev"), "signed-state", "ciphertext")
	if err := s.Publish(context.Background(), o); err != nil {
		t.Fatal(err)
	}
	name, _ := storage.Name(o.Kind, o.Scope, o.Rev)
	var m ocispec.Manifest
	if err := json.Unmarshal(r.manifests[name], &m); err != nil {
		t.Fatal(err)
	}
	if len(m.Layers) != 2 || m.Layers[0].Digest != o.Rev || m.Layers[1].Digest != digest.FromBytes(o.Cipher) {
		t.Fatalf("layers do not reference signed state and ciphertext: %+v", m.Layers)
	}
	if m.Subject != nil {
		t.Fatal("a subject would trigger the racy referrers fallback")
	}
	if r.puts != 1 {
		t.Fatalf("manifest puts = %d", r.puts)
	}
	// Republishing is idempotent: nothing is uploaded again.
	blobPuts := r.blobPuts
	if err := s.Publish(context.Background(), o); err != nil {
		t.Fatal(err)
	}
	if r.puts != 1 || r.blobPuts != blobPuts {
		t.Fatalf("republish uploaded again: manifests=%d blobs=%d->%d", r.puts, blobPuts, r.blobPuts)
	}
}

func TestOCIFetchRejectsTamperedContent(t *testing.T) {
	r, s := newFakeRegistry(t)
	ctx := context.Background()
	o := storagetest.Object(storage.KindState, storagetest.Scope("secrets/dev"), "signed-state", "ciphertext")
	if err := s.Publish(ctx, o); err != nil {
		t.Fatal(err)
	}
	name, _ := storage.Name(o.Kind, o.Scope, o.Rev)

	// The registry serves other bytes under the ciphertext digest.
	r.mu.Lock()
	r.blobs[digest.FromBytes(o.Cipher).String()] = []byte("tampered")
	r.mu.Unlock()
	if _, err := s.Fetch(ctx, o.Kind, o.Scope, o.Rev); err == nil {
		t.Fatal("tampered ciphertext accepted")
	}

	// The tag is retargeted at another revision's manifest.
	other := storagetest.Object(storage.KindState, storagetest.Scope("secrets/dev"), "signed-state-2", "ciphertext-2")
	if err := s.Publish(ctx, other); err != nil {
		t.Fatal(err)
	}
	otherName, _ := storage.Name(other.Kind, other.Scope, other.Rev)
	r.mu.Lock()
	r.manifests[name] = r.manifests[otherName]
	r.mu.Unlock()
	if _, err := s.Fetch(ctx, o.Kind, o.Scope, o.Rev); !errors.Is(err, storage.ErrCorrupt) {
		t.Fatalf("retargeted tag: %v", err)
	}
	if err := s.Publish(ctx, o); !errors.Is(err, storage.ErrCorrupt) {
		t.Fatalf("publish over a retargeted tag: %v", err)
	}
}

func TestOCIPublishFailsWhenABlobDisappears(t *testing.T) {
	r, s := newFakeRegistry(t)
	ctx := context.Background()
	o := storagetest.Object(storage.KindState, storagetest.Scope("secrets/dev"), "signed-state", "ciphertext")
	if err := s.Publish(ctx, o); err != nil {
		t.Fatal(err)
	}
	// A registry GC drops the ciphertext after the manifest exists; republishing must not acknowledge.
	r.mu.Lock()
	delete(r.blobs, digest.FromBytes(o.Cipher).String())
	r.mu.Unlock()
	if err := s.Publish(ctx, o); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("publish acknowledged a missing blob: %v", err)
	}
}

func TestOCIDiscoverIgnoresForeignTags(t *testing.T) {
	r, s := newFakeRegistry(t)
	ctx := context.Background()
	o := storagetest.Object(storage.KindControl, "", "signed-control", "")
	if err := s.Publish(ctx, o); err != nil {
		t.Fatal(err)
	}
	r.mu.Lock()
	for _, tag := range []string{"latest", "c-short", "c-" + strings.Repeat("z", 64), "sha256-fallback"} {
		r.manifests[tag] = []byte("{}")
	}
	r.mu.Unlock()
	revs, err := s.Discover(ctx, storage.KindControl, "")
	if err != nil || len(revs) != 1 || revs[0] != o.Rev {
		t.Fatalf("discover = %v %v", revs, err)
	}
	if s.Capabilities().PhysicalDelete {
		t.Fatal("OCI cannot delete through the registry API")
	}
}

var _ = bytes.Equal

func TestOCIDiscoverTreatsAnUnknownRepositoryAsEmpty(t *testing.T) {
	r, s := newFakeRegistry(t)
	r.unknownWhenEmpty = true
	ctx := context.Background()
	for _, kind := range []storage.Kind{storage.KindControl, storage.KindRequest} {
		if revs, err := s.Discover(ctx, kind, ""); err != nil || len(revs) != 0 {
			t.Fatalf("%s before the first push: %v %v", kind, revs, err)
		}
	}
	o := storagetest.Object(storage.KindControl, "", "signed-control", "")
	if err := s.Publish(ctx, o); err != nil {
		t.Fatal(err)
	}
	if revs, err := s.Discover(ctx, storage.KindControl, ""); err != nil || len(revs) != 1 {
		t.Fatalf("after the first push: %v %v", revs, err)
	}
}
