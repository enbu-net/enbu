package storage

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"github.com/opencontainers/go-digest"
	"oras.land/oras-go/v2/registry/remote/auth"
)

// Channels establish that cancellation happens while an actual HTTP call is
// waiting. The deadline is only a deadlock watchdog, never an ordering input.
func TestRemoteCancellationWhileWaiting(t *testing.T) {
	for _, backend := range []string{"oci", "s3"} {
		for _, op := range []string{"discover", "head", "blob", "publish", "delete"} {
			if backend == "oci" && op == "delete" {
				continue // OCI physical deletion uses a separate provider API.
			}
			t.Run(backend+"/"+op, func(t *testing.T) {
				watchdog, stop := context.WithTimeout(t.Context(), 10*time.Second)
				defer stop()
				entered, disconnected, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
				var requests atomic.Int32
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if requests.Add(1) == 1 {
						// Finish reading uploads before observing disconnect: an
						// unread request body prevents HTTP/1's background read.
						_, _ = io.Copy(io.Discard, r.Body)
						close(entered)
						select {
						case <-r.Context().Done():
							close(disconnected)
						case <-release:
						}
						return
					}
					if backend == "oci" {
						w.Header().Set("Content-Type", "application/json")
						_, _ = io.WriteString(w, `{"name":"team/secrets","tags":[]}`)
					} else {
						w.Header().Set("Content-Type", "application/xml")
						_, _ = io.WriteString(w, `<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Name>team</Name><IsTruncated>false</IsTruncated></ListBucketResult>`)
					}
				}))
				defer server.Close()
				defer close(release)
				var store Store
				if backend == "oci" {
					var err error
					store, err = NewOCI(strings.TrimPrefix(server.URL, "http://")+"/team/secrets", func(context.Context, string) (auth.Credential, error) {
						return auth.EmptyCredential, nil
					}, true)
					if err != nil {
						t.Fatal(err)
					}
				} else {
					client, err := minio.New(strings.TrimPrefix(server.URL, "http://"), &minio.Options{
						Region: "us-east-1", BucketLookup: minio.BucketLookupPath,
						Creds: credentials.NewStaticV4("fixture-access", "fixture-secret", ""),
					})
					if err != nil {
						t.Fatal(err)
					}
					store = NewS3(client, "team", "secrets")
				}
				head := []byte("fixture signed header")
				object := Object{Kind: KindState, Scope: StateScope("fixture-workspace", "fixture-resource"), Rev: digest.FromBytes(head), Head: head}
				ctx, cancel := context.WithCancel(watchdog)
				defer cancel()
				result := make(chan error, 1)
				go func() {
					var err error
					switch op {
					case "discover":
						_, err = store.Discover(ctx, object.Kind, object.Scope)
					case "head":
						_, err = store.FetchHead(ctx, object.Kind, object.Scope, object.Rev)
					case "blob":
						var reader io.ReadCloser
						reader, err = store.OpenBlob(ctx, object.Kind, object.Scope, object.Rev, 0)
						if reader != nil {
							_ = reader.Close()
						}
					case "publish":
						err = store.Publish(ctx, object)
					case "delete":
						err = store.Delete(ctx, object.Kind, object.Scope, object.Rev)
					}
					result <- err
				}()
				select {
				case <-entered:
				case err := <-result:
					t.Fatalf("operation returned before reaching HTTP: %v", err)
				case <-watchdog.Done():
					t.Fatal("operation never reached HTTP")
				}
				cancel()
				select {
				case err := <-result:
					if !errors.Is(err, context.Canceled) {
						t.Fatalf("cancellation cause was lost: %v", err)
					}
				case <-watchdog.Done():
					t.Fatal("operation did not stop after cancellation")
				}
				select {
				case <-disconnected:
				case <-watchdog.Done():
					t.Fatal("canceled HTTP request remained connected")
				}
				// A canceled request must not poison the shared transport/client.
				if refs, err := store.Discover(watchdog, object.Kind, object.Scope); err != nil || len(refs) != 0 {
					t.Fatalf("fresh request could not recover: refs=%v err=%v", refs, err)
				}
			})
		}
	}
}
