package storage

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2/registry/remote/auth"
)

func TestRemoteInterruptedResponseBody(t *testing.T) {
	for _, transport := range []string{"http", "https"} {
		for _, backend := range []string{"oci", "s3"} {
			for _, phase := range []string{"manifest", "frame", "head", "payload"} {
				if backend == "s3" && phase == "manifest" || backend == "oci" && phase == "frame" {
					continue
				}
				for _, interruption := range []string{"cancel", "disconnect"} {
					t.Run(transport+"/"+backend+"/"+phase+"/"+interruption, func(t *testing.T) {
						watchdog, stop := context.WithTimeout(t.Context(), 10*time.Second)
						defer stop()
						head := bytes.Repeat([]byte("signed-header-fixture"), 32)
						payload := bytes.Repeat([]byte("encrypted-payload-fixture"), 512)
						object := Object{Kind: KindState, Scope: StateScope("team", "default"), Rev: digest.FromBytes(head), Head: head, Payload: payload}
						_, manifest, desc, err := manifestFor(object)
						if err != nil {
							t.Fatal(err)
						}
						framed := frame(object)
						_, payloadAt, err := readHead(bytes.NewReader(framed), int64(len(framed)), object.Rev)
						headAt := int64(len(binary.AppendUvarint(nil, uint64(len(head)))))
						if err != nil {
							t.Fatal(err)
						}
						entered, consumed, disconnected, release := make(chan struct{}), make(chan struct{}), make(chan struct{}), make(chan struct{})
						drop := make(chan struct{})
						var armed, triggered atomic.Bool
						handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
							recorder := httptest.NewRecorder()
							target := false
							if backend == "oci" {
								var data []byte
								var media, dgst string
								switch {
								case strings.Contains(r.URL.Path, "/manifests/"):
									data, media, dgst = manifest, ocispec.MediaTypeImageManifest, desc.Digest.String()
									target = phase == "manifest"
								case strings.HasSuffix(r.URL.Path, "/blobs/"+object.Rev.String()):
									data, media, dgst = head, "application/octet-stream", object.Rev.String()
									target = phase == "head"
								case strings.HasSuffix(r.URL.Path, "/blobs/"+digest.FromBytes(payload).String()):
									data, media, dgst = payload, "application/octet-stream", digest.FromBytes(payload).String()
									target = phase == "payload"
								default:
									http.NotFound(w, r)
									return
								}
								recorder.Header().Set("Content-Type", media)
								recorder.Header().Set("Content-Length", strconv.Itoa(len(data)))
								recorder.Header().Set("Docker-Content-Digest", dgst)
								if r.Method == http.MethodGet {
									_, _ = recorder.Write(data)
								}
							} else {
								recorder.Header().Set("Content-Type", "application/octet-stream")
								recorder.Header().Set("ETag", `"fixture-etag"`)
								recorder.Header().Set("Last-Modified", "Mon, 02 Jan 2006 15:04:05 GMT")
								http.ServeContent(recorder, r, "fixture", time.Time{}, bytes.NewReader(framed))
								var start int64
								if _, err := fmt.Sscanf(r.Header.Get("Range"), "bytes=%d-", &start); err != nil && r.Header.Get("Range") != "" {
									t.Errorf("unexpected range %q", r.Header.Get("Range"))
								}
								switch phase {
								case "frame":
									target = start == 0
								case "head":
									target = start == headAt
								case "payload":
									target = start >= payloadAt
								}
							}
							for key, values := range recorder.Header() {
								w.Header()[key] = values
							}
							w.WriteHeader(recorder.Code)
							body := recorder.Body.Bytes()
							if r.Method == http.MethodGet && target && len(body) > 1 && armed.Load() && triggered.CompareAndSwap(false, true) {
								// Flush a prefix but withhold the remaining declared bytes.
								_, _ = w.Write(body[:1])
								w.(http.Flusher).Flush()
								close(entered)
								select {
								case <-r.Context().Done():
									close(disconnected)
								case <-drop:
									close(disconnected)
								case <-release:
								}
								return
							}
							_, _ = w.Write(body)
						})
						server := httptest.NewUnstartedServer(handler)
						if transport == "https" {
							server.StartTLS()
						} else {
							server.Start()
						}
						defer server.Close()
						defer close(release)
						var store Store
						endpoint := strings.TrimPrefix(strings.TrimPrefix(server.URL, "http://"), "https://")
						if backend == "oci" {
							store, err = NewOCI(endpoint+"/team/secrets", func(context.Context, string) (auth.Credential, error) {
								return auth.EmptyCredential, nil
							}, transport == "http")
							if err == nil {
								// Trust only this fixture server, without changing global TLS state.
								withHTTPClient(store, server.Client())
							}
						} else {
							var client *minio.Client
							client, err = minio.New(endpoint, &minio.Options{
								Region: "us-east-1", BucketLookup: minio.BucketLookupPath,
								Creds:  credentials.NewStaticV4("fixture-access", "fixture-secret", ""),
								Secure: transport == "https", Transport: server.Client().Transport,
							})
							if err == nil {
								store = NewS3(client, "team", "secrets")
							}
						}
						if err != nil {
							t.Fatal(err)
						}
						read := func(ctx context.Context, signal bool) ([]byte, error) {
							if phase != "payload" {
								return store.FetchHead(ctx, object.Kind, object.Scope, object.Rev)
							}
							rc, err := store.OpenPayload(ctx, object.Kind, object.Scope, object.Rev)
							if err != nil {
								return nil, err
							}
							defer func() { _ = rc.Close() }()
							prefix := make([]byte, 1)
							if _, err := io.ReadFull(rc, prefix); err != nil {
								return nil, err
							}
							if signal {
								close(consumed)
							}
							rest, err := io.ReadAll(rc)
							return append(prefix, rest...), err
						}
						want := head
						if phase == "payload" {
							want = payload
						}
						if data, err := read(watchdog, false); err != nil || !bytes.Equal(data, want) {
							t.Fatalf("unmodified transport control failed: bytes=%d err=%v", len(data), err)
						}
						ctx, cancel := context.WithCancel(watchdog)
						defer cancel()
						armed.Store(true)
						type response struct {
							data []byte
							err  error
						}
						result := make(chan response, 1)
						go func() { data, err := read(ctx, phase == "payload"); result <- response{data, err} }()
						select {
						case <-entered:
						case result := <-result:
							t.Fatalf("read did not reach partial response: %v", result.err)
						case <-watchdog.Done():
							t.Fatal("partial response boundary was not reached")
						}
						if phase == "payload" {
							select {
							case <-consumed:
							case <-watchdog.Done():
								t.Fatal("client did not consume the payload prefix")
							}
						}
						if interruption == "cancel" {
							cancel()
						} else {
							close(drop)
						}
						select {
						case result := <-result:
							if interruption == "cancel" && (!errors.Is(result.err, context.Canceled) || len(result.data) >= len(want)) {
								t.Fatalf("partial response accepted or cancellation lost: bytes=%d err=%v", len(result.data), result.err)
							}
							if interruption == "disconnect" && result.err == nil && !bytes.Equal(result.data, want) {
								t.Fatal("interrupted response accepted incomplete or changed data")
							}
						case <-watchdog.Done():
							t.Fatal("response reader did not stop after cancellation")
						}
						select {
						case <-disconnected:
						case <-watchdog.Done():
							t.Fatal("partial response remained connected")
						}
						armed.Store(false)
						if data, err := read(watchdog, false); err != nil || !bytes.Equal(data, want) {
							t.Fatalf("fresh read failed after cancellation: bytes=%d err=%v", len(data), err)
						}
					})
				}
			}
		}
	}
}

// withHTTPClient makes an OCI store send its requests through client.
func withHTTPClient(s Store, client *http.Client) {
	s.(ociStore).repo.Client.(*auth.Client).Client = client
}
