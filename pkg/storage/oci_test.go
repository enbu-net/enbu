package storage

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
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
