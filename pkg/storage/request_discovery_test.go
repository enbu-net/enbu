package storage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"github.com/opencontainers/go-digest"
	"oras.land/oras-go/v2/registry/remote/auth"
)

// The limit must stop discovery itself, not only reject its complete result.
// A third page is deliberately available after the first excess request ref.
func TestRemoteRequestDiscoveryStopsAtBudget(t *testing.T) {
	for _, backend := range []string{"oci", "s3"} {
		for _, mode := range []string{"boundary", "overflow", "duplicate-overflow", "state-overflow"} {
			t.Run(backend+"/"+mode, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
				defer cancel()
				kind, scope := KindRequest, ""
				if mode == "state-overflow" {
					kind, scope = KindState, StateScope("budget-workspace", "resource")
				}
				var names []string
				var want []digest.Digest
				for i := range 10001 {
					rev := digest.FromString(fmt.Sprintf("request-budget-%d", i))
					name, err := Name(kind, scope, rev)
					if err != nil {
						t.Fatal(err)
					}
					want, names = append(want, rev), append(names, name)
				}
				var recovered atomic.Bool
				var pages atomic.Int32
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					pages.Add(1)
					page := r.URL.Query().Get("last") + r.URL.Query().Get("continuation-token")
					if page == "unexpected" {
						w.WriteHeader(http.StatusForbidden)
						return
					}
					selected := names[:10000]
					truncated := mode != "boundary"
					next := "second"
					if page == "second" {
						selected, next = names[10000:], "unexpected"
						truncated = mode != "state-overflow"
						if mode == "duplicate-overflow" {
							selected = names[:1]
						}
					}
					if recovered.Load() {
						selected, truncated = names[:1], false
					}
					if backend == "oci" {
						w.Header().Set("Content-Type", "application/json")
						if truncated {
							w.Header().Set("Link", `</v2/team/secrets/tags/list?last=`+next+`>; rel="next"`)
						}
						_ = json.NewEncoder(w).Encode(map[string]any{"name": "team/secrets", "tags": selected})
						return
					}
					w.Header().Set("Content-Type", "application/xml")
					_, _ = fmt.Fprintf(w, `<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Name>team</Name><IsTruncated>%t</IsTruncated><NextContinuationToken>%s</NextContinuationToken>`, truncated, next)
					for _, name := range selected {
						_, _ = fmt.Fprintf(w, `<Contents><Key>secrets/revisions/%s</Key><LastModified>2026-01-01T00:00:00Z</LastModified><ETag>"fixture"</ETag><Size>1</Size></Contents>`, name)
					}
					_, _ = io.WriteString(w, `</ListBucketResult>`)
				}))
				defer server.Close()
				var store Store
				var err error
				if backend == "oci" {
					store, err = NewOCI(strings.TrimPrefix(server.URL, "http://")+"/team/secrets", func(context.Context, string) (auth.Credential, error) { return auth.EmptyCredential, nil }, true)
				} else {
					var client *minio.Client
					client, err = minio.New(strings.TrimPrefix(server.URL, "http://"), &minio.Options{Region: "us-east-1", BucketLookup: minio.BucketLookupPath, Creds: credentials.NewStaticV4("fixture-access", "fixture-secret", "")})
					if err == nil {
						store = NewS3(client, "team", "secrets")
					}
				}
				if err != nil {
					t.Fatal(err)
				}
				refs, err := store.Discover(ctx, kind, scope)
				if mode == "overflow" || mode == "duplicate-overflow" {
					if !errors.Is(err, ErrDiscoveryLimit) || refs != nil || pages.Load() != 2 {
						t.Fatalf("discovery did not stop at its request budget: refs=%d pages=%d err=%v", len(refs), pages.Load(), err)
					}
				} else {
					if mode == "boundary" {
						want = want[:10000]
					}
					slices.Sort(want)
					if err != nil || !reflect.DeepEqual(refs, want) {
						t.Fatalf("valid discovery boundary lost refs: got=%d want=%d err=%v", len(refs), len(want), err)
					}
				}
				recovered.Store(true)
				pages.Store(0)
				refs, err = store.Discover(ctx, kind, scope)
				if err != nil || len(refs) != 1 || refs[0] != digest.FromString("request-budget-0") || pages.Load() != 1 {
					t.Fatalf("same client did not recover exact discovery: refs=%d pages=%d err=%v", len(refs), pages.Load(), err)
				}
			})
		}
	}
}

func TestLocalRequestDiscoveryBudget(t *testing.T) {
	dir := t.TempDir()
	revisions := filepath.Join(dir, revisionDir)
	if err := os.MkdirAll(revisions, 0o700); err != nil {
		t.Fatal(err)
	}
	var want []digest.Digest
	for i := range 10001 {
		rev := digest.FromString(fmt.Sprintf("request-budget-%d", i))
		name, err := Name(KindRequest, "", rev)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(revisions, name), nil, 0o600); err != nil {
			t.Fatal(err)
		}
		want = append(want, rev)
	}
	store := NewLocal(dir)
	if refs, err := store.Discover(t.Context(), KindRequest, ""); !errors.Is(err, ErrDiscoveryLimit) || refs != nil {
		t.Fatalf("local discovery returned an over-budget listing: refs=%d err=%v", len(refs), err)
	}
	name, err := Name(KindRequest, "", want[len(want)-1])
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(revisions, name)); err != nil {
		t.Fatal(err)
	}
	want = want[:10000]
	slices.Sort(want)
	refs, err := store.Discover(t.Context(), KindRequest, "")
	if err != nil || !reflect.DeepEqual(refs, want) {
		t.Fatalf("local exact budget did not recover: refs=%d err=%v", len(refs), err)
	}
}
