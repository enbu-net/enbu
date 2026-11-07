package storage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"github.com/opencontainers/go-digest"
	"oras.land/oras-go/v2/registry/remote/auth"
)

// Permissions can change after a valid first page. A failed later page must
// remain an error, and restoring access must not require a new storage client.
func TestRemotePermissionLossDuringPagination(t *testing.T) {
	for _, backend := range []string{"oci", "s3"} {
		for _, status := range []int{http.StatusUnauthorized, http.StatusForbidden} {
			for _, operation := range []string{"discover", "scopes"} {
				t.Run(backend+"/"+strconv.Itoa(status)+"/"+operation, func(t *testing.T) {
					ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
					defer cancel() // Deadlock guard only; HTTP pagination defines the order.
					scope := StateScope("permission-workspace", "permission-resource")
					rev := digest.FromString("signed fixture")
					name, err := Name(KindState, scope, rev)
					if err != nil {
						t.Fatal(err)
					}
					var restored atomic.Bool
					var pages, denied atomic.Int32
					server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						if r.Method != http.MethodGet {
							t.Errorf("unexpected request method %s", r.Method)
						}
						next := r.URL.Query().Get("last") != "" || r.URL.Query().Get("continuation-token") != ""
						if next && !restored.Load() {
							denied.Add(1)
							if backend == "oci" {
								w.Header().Set("Content-Type", "application/json")
								w.WriteHeader(status)
								_, _ = io.WriteString(w, `{"errors":[{"code":"DENIED","message":"permission revoked"}]}`)
							} else {
								w.Header().Set("Content-Type", "application/xml")
								w.WriteHeader(status)
								_, _ = io.WriteString(w, `<Error><Code>AccessDenied</Code><Message>permission revoked</Message><Resource>/team</Resource><RequestId>fixture</RequestId></Error>`)
							}
							return
						}
						pages.Add(1)
						truncated := !restored.Load()
						if backend == "oci" {
							w.Header().Set("Content-Type", "application/json")
							if truncated {
								w.Header().Set("Link", `</v2/team/secrets/tags/list?last=next-page>; rel="next"`)
							}
							_ = json.NewEncoder(w).Encode(map[string]any{"name": "team/secrets", "tags": []string{name}})
						} else {
							w.Header().Set("Content-Type", "application/xml")
							_, _ = fmt.Fprintf(w, `<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Name>team</Name><IsTruncated>%t</IsTruncated><NextContinuationToken>next-page</NextContinuationToken><Contents><Key>secrets/revisions/%s</Key><LastModified>2026-01-01T00:00:00Z</LastModified><ETag>"fixture"</ETag><Size>1</Size></Contents></ListBucketResult>`, truncated, name)
						}
					}))
					defer server.Close()
					var store Store
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
					list := func() ([]string, error) {
						if operation == "scopes" {
							return store.Scopes(ctx)
						}
						refs, err := store.Discover(ctx, KindState, scope)
						var out []string
						for _, ref := range refs {
							out = append(out, ref.String())
						}
						return out, err
					}
					if _, err := list(); err == nil || errors.Is(err, ErrNotFound) {
						t.Fatalf("later-page permission denial became successful or missing storage: %v", err)
					}
					if pages.Load() != 1 || denied.Load() == 0 {
						t.Fatalf("denial did not follow a valid page: pages=%d denied=%d", pages.Load(), denied.Load())
					}
					restored.Store(true)
					want := []string{rev.String()}
					if operation == "scopes" {
						want = []string{scope}
					}
					got, err := list()
					if err != nil || !reflect.DeepEqual(got, want) {
						t.Fatalf("same client did not recover exact listing: got=%v want=%v err=%v", got, want, err)
					}
				})
			}
		}
	}
}
