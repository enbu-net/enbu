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

func TestOCIPutDuplicateConfigDescriptor(t *testing.T) {
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
	o := Object{MediaType: "application/vnd.enbu.config.v1+json", Data: []byte("{}")}
	if err := s.Put(context.Background(), "secret", o, ""); err != nil {
		t.Fatal(err)
	}
	var got ocispec.Manifest
	if err := json.Unmarshal(<-manifests, &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Layers) != 1 || got.Config.MediaType != o.MediaType || got.Config.Digest != digest.FromBytes(o.Data) || got.Config.Size != int64(len(o.Data)) {
		t.Fatalf("manifest lost the config or layer: %+v", got)
	}
	if got.Layers[0].MediaType != got.Config.MediaType || got.Layers[0].Digest != got.Config.Digest || got.Layers[0].Size != got.Config.Size {
		t.Fatalf("duplicate descriptors differ: config=%+v layer=%+v", got.Config, got.Layers[0])
	}
}
