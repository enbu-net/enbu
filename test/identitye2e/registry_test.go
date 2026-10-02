//go:build identitye2e

package identitye2e

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// registryFixture implements the OCI distribution endpoints used by oras. It
// stores real manifests and blobs, so CLI E2E exercises the production Registry.
type registryFixture struct {
	mu        sync.Mutex
	blobs     map[string][]byte
	manifests map[string][]byte
	tags      map[string]map[string]string
	uploads   map[string][]byte
	next      int
}

func newRegistry() *registryFixture {
	return &registryFixture{blobs: map[string][]byte{}, manifests: map[string][]byte{}, tags: map[string]map[string]string{}, uploads: map[string][]byte{}}
}
func contentDigest(b []byte) string { return fmt.Sprintf("sha256:%x", sha256.Sum256(b)) }

func (f *registryFixture) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	w.Header().Set("Docker-Distribution-API-Version", "registry/2.0")
	if r.URL.Path == "/v2/" {
		w.WriteHeader(http.StatusOK)
		return
	}
	path := strings.TrimPrefix(r.URL.Path, "/v2/")
	if repo, ok := strings.CutSuffix(path, "/tags/list"); ok {
		var tags []string
		for tag := range f.tags[repo] {
			tags = append(tags, tag)
		}
		sort.Strings(tags)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"name": repo, "tags": tags})
		return
	}
	if repo, ref, ok := strings.Cut(path, "/manifests/"); ok {
		if r.Method == http.MethodPut {
			b, err := io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, err.Error(), 500)
				return
			}
			d := contentDigest(b)
			f.manifests[d] = b
			if !strings.HasPrefix(ref, "sha256:") {
				if f.tags[repo] == nil {
					f.tags[repo] = map[string]string{}
				}
				f.tags[repo][ref] = d
			}
			w.Header().Set("Docker-Content-Digest", d)
			w.Header().Set("Location", r.URL.Path)
			w.WriteHeader(http.StatusCreated)
			return
		}
		d := ref
		if !strings.HasPrefix(ref, "sha256:") {
			d = f.tags[repo][ref]
		}
		b, exists := f.manifests[d]
		if !exists {
			f.notFound(w, "MANIFEST_UNKNOWN")
			return
		}
		f.serveContent(w, r, b, "application/vnd.oci.image.manifest.v1+json")
		return
	}
	if repo, id, ok := strings.Cut(path, "/blobs/uploads/"); ok {
		if r.Method == http.MethodPost {
			f.next++
			id = strconv.Itoa(f.next)
			f.uploads[id] = nil
			w.Header().Set("Location", "/v2/"+repo+"/blobs/uploads/"+id)
			w.Header().Set("Docker-Upload-UUID", id)
			w.WriteHeader(http.StatusAccepted)
			return
		}
		if r.Method == http.MethodPatch || r.Method == http.MethodPut {
			b, err := io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, err.Error(), 500)
				return
			}
			f.uploads[id] = append(f.uploads[id], b...)
			if r.Method == http.MethodPut {
				d := r.URL.Query().Get("digest")
				if contentDigest(f.uploads[id]) != d {
					http.Error(w, "digest mismatch", 400)
					return
				}
				f.blobs[d] = f.uploads[id]
				delete(f.uploads, id)
				w.Header().Set("Location", "/v2/"+repo+"/blobs/"+d)
				w.Header().Set("Docker-Content-Digest", d)
				w.WriteHeader(http.StatusCreated)
				return
			}
			w.Header().Set("Location", r.URL.Path)
			w.Header().Set("Range", fmt.Sprintf("0-%d", len(f.uploads[id])-1))
			w.WriteHeader(http.StatusAccepted)
			return
		}
	}
	if _, d, ok := strings.Cut(path, "/blobs/"); ok {
		b, exists := f.blobs[d]
		if !exists {
			f.notFound(w, "BLOB_UNKNOWN")
			return
		}
		f.serveContent(w, r, b, "application/octet-stream")
		return
	}
	f.notFound(w, "NAME_UNKNOWN")
}
func (f *registryFixture) serveContent(w http.ResponseWriter, r *http.Request, b []byte, media string) {
	w.Header().Set("Content-Type", media)
	w.Header().Set("Content-Length", strconv.Itoa(len(b)))
	w.Header().Set("Docker-Content-Digest", contentDigest(b))
	w.WriteHeader(http.StatusOK)
	if r.Method != http.MethodHead {
		_, _ = w.Write(b)
	}
}
func (f *registryFixture) notFound(w http.ResponseWriter, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusNotFound)
	_ = json.NewEncoder(w).Encode(map[string]any{"errors": []map[string]string{{"code": code, "message": "fixture not found"}}})
}
