package storage

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2/registry/remote/auth"
)

func TestOCIRefPutManifestReferencesBlob(t *testing.T) {
	manifests := make(chan []byte, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodHead && strings.Contains(r.URL.Path, "/blobs/"):
			w.Header().Set("Content-Length", "2")
			w.WriteHeader(http.StatusOK)
		case r.Method == http.MethodPut && strings.Contains(r.URL.Path, "/manifests/"):
			manifest, err := io.ReadAll(r.Body)
			if err != nil {
				t.Error(err)
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			manifests <- manifest
			w.Header().Set("Docker-Content-Digest", digest.FromBytes(manifest).String())
			w.WriteHeader(http.StatusCreated)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	s, err := NewOCI(strings.TrimPrefix(server.URL, "http://")+"/enbu", func(context.Context, string) (auth.Credential, error) {
		return auth.EmptyCredential, nil
	}, true)
	if err != nil {
		t.Fatal(err)
	}
	target := digest.FromString("ab")
	if err := s.Refs.Put(context.Background(), "secret", target, ""); err != nil {
		t.Fatal(err)
	}
	var got ocispec.Manifest
	if err := json.Unmarshal(<-manifests, &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Layers) != 1 || got.Layers[0].Digest != target || got.Layers[0].Size != 2 {
		t.Fatalf("manifest does not reference the target blob: %+v", got)
	}
	if got.Config.Digest != digest.FromBytes([]byte("{}")) {
		t.Fatalf("unexpected config: %+v", got.Config)
	}
}

// fakeRegistry implements the subset of the distribution API that Store uses.
type fakeRegistry struct {
	mu        sync.Mutex
	blobs     map[string][]byte
	manifests map[string][]byte // by tag and by digest
	puts      int
}

func newFakeRegistry(t *testing.T) (*fakeRegistry, *Store) {
	t.Helper()
	r := &fakeRegistry{blobs: map[string][]byte{}, manifests: map[string][]byte{}}
	server := httptest.NewServer(r)
	t.Cleanup(server.Close)
	s, err := NewOCI(strings.TrimPrefix(server.URL, "http://")+"/enbu", func(context.Context, string) (auth.Credential, error) {
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
	contract(t, s)
}

func TestOCIBlobPutSkipsExistingBlob(t *testing.T) {
	r, s := newFakeRegistry(t)
	d := putBlob(t, s, "same")
	r.mu.Lock()
	r.blobs[d.String()] = []byte("sentinel")
	r.mu.Unlock()
	if again := putBlob(t, s, "same"); again != d {
		t.Fatalf("digest=%s", again)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if string(r.blobs[d.String()]) != "sentinel" {
		t.Fatal("existing blob was uploaded again")
	}
}

func TestOCIRefRejectsTamperedBlob(t *testing.T) {
	r, s := newFakeRegistry(t)
	d := putBlob(t, s, "secret")
	r.mu.Lock()
	r.blobs[d.String()] = []byte("tampered")
	r.mu.Unlock()
	rc, err := s.Blobs.Open(context.Background(), d)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rc.Close() }()
	if _, err := io.ReadAll(rc); err == nil {
		t.Fatal("tampered blob was accepted")
	}
}
