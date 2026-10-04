package storage

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"github.com/opencontainers/go-digest"
	"github.com/yashikota/minis3"
)

func minis3Store(t *testing.T) (*Store, s3) {
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
	return NewS3(client, "enbu-test", "workspace"), s3{client, "enbu-test", "workspace"}
}

func TestS3Minis3Contract(t *testing.T) {
	st, _ := minis3Store(t)
	contract(t, st)
}

func TestS3ListCanceled(t *testing.T) {
	st, _ := minis3Store(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := st.Refs.List(ctx, ""); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled list: %v", err)
	}
}

func TestS3LargeBlobAndConditionalRef(t *testing.T) {
	st, _ := minis3Store(t)
	ctx := context.Background()
	data := bytes.Repeat([]byte("x"), MaxPayloadBytes)
	d, err := st.Blobs.Put(ctx, bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	rc, err := st.Blobs.Open(ctx, d)
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(rc)
	_ = rc.Close()
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("large blob round trip: %v", err)
	}
	if err := st.Refs.Put(ctx, "large", d, ""); err != nil {
		t.Fatal(err)
	}
	if err := st.Refs.Put(ctx, "large", d, "stale"); !errors.Is(err, ErrConflict) {
		t.Fatalf("large stale write: %v", err)
	}
}

func TestNewS3ClientCredentials(t *testing.T) {
	for _, source := range []string{"environment", "profile"} {
		t.Run(source, func(t *testing.T) {
			t.Setenv("AWS_ACCESS_KEY_ID", "")
			t.Setenv("AWS_ACCESS_KEY", "")
			t.Setenv("AWS_SECRET_ACCESS_KEY", "")
			t.Setenv("AWS_SECRET_KEY", "")
			t.Setenv("AWS_SESSION_TOKEN", "")
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
			target := digest.FromString("secret")
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet || r.URL.Path != "/enbu-test/workspace/refs/object" {
					t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
				}
				if !strings.Contains(r.Header.Get("Authorization"), "Credential=test-key/") ||
					!strings.Contains(r.Header.Get("Authorization"), "/test-region/s3/aws4_request") ||
					r.Header.Get("X-Amz-Security-Token") != "test-token" {
					t.Error("request did not use the selected credentials and region")
				}
				w.Header().Set("ETag", "\"test-etag\"")
				w.Header().Set("Last-Modified", "Mon, 02 Jan 2006 15:04:05 GMT")
				_, _ = w.Write([]byte(target))
			}))
			t.Cleanup(server.Close)
			client, err := NewS3Client(server.URL, "", true)
			if err != nil {
				t.Fatal(err)
			}
			store := NewS3(client, "enbu-test", "workspace")
			got, version, err := store.Refs.Get(context.Background(), "object")
			if err != nil || got != target || version != "test-etag" {
				t.Fatalf("authenticated read: got=%s version=%q, err=%v", got, version, err)
			}
		})
	}
}

func TestNewS3ClientEndpointValidation(t *testing.T) {
	for _, endpoint := range []string{"relative", "ftp://example.com", "https://user:password@example.com", "https://example.com/path", "https://example.com?query=1", "https://example.com#fragment"} {
		if _, err := NewS3Client(endpoint, "us-east-1", false); err == nil {
			t.Fatalf("accepted endpoint %q", endpoint)
		}
	}
	client, err := NewS3Client("", "us-east-1", false)
	if err != nil {
		t.Fatal(err)
	}
	if got := client.EndpointURL().String(); got != "https://s3.amazonaws.com" {
		t.Fatalf("default endpoint=%q", got)
	}
}

func TestS3Minis3BucketRoot(t *testing.T) {
	st, raw := minis3Store(t)
	raw.prefix = ""
	if got := raw.refKey("object"); got != "refs/object" {
		t.Fatalf("bucket root key = %q", got)
	}
	contract(t, NewS3(raw.client, raw.bucket, ""))
	_ = st
}

func TestS3Minis3PrefixAndPagination(t *testing.T) {
	st, raw := minis3Store(t)
	ctx := context.Background()
	for i := range 1003 {
		if _, err := raw.client.PutObject(ctx, raw.bucket, raw.refKey(fmt.Sprintf("key-%04d", i)), bytes.NewReader([]byte("test")), 4, minio.PutObjectOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	other := NewS3(raw.client, raw.bucket, "workspace-other")
	if err := other.Refs.Put(ctx, "foreign", putBlob(t, other, "foreign"), ""); err != nil {
		t.Fatal(err)
	}
	keys, err := st.Refs.List(ctx, "key-")
	if err != nil || len(keys) != 1003 {
		t.Fatalf("pagination=%d %v", len(keys), err)
	}
	keys, err = other.Refs.List(ctx, "")
	if err != nil || !reflect.DeepEqual(keys, []string{"foreign"}) {
		t.Fatalf("prefix=%v %v", keys, err)
	}
}

func TestS3Minis3Corruption(t *testing.T) {
	st, raw := minis3Store(t)
	ctx := context.Background()
	if _, err := raw.client.PutObject(ctx, raw.bucket, raw.refKey("bad"), bytes.NewReader([]byte("{}")), 2, minio.PutObjectOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := st.Refs.Get(ctx, "bad"); err == nil || errors.Is(err, ErrNotFound) {
		t.Fatalf("corrupt ref=%v", err)
	}
	d := digest.FromString("secret")
	key, _ := raw.blobKey(d)
	if _, err := raw.client.PutObject(ctx, raw.bucket, key, bytes.NewReader([]byte("tampered")), 8, minio.PutObjectOptions{}); err != nil {
		t.Fatal(err)
	}
	rc, err := st.Blobs.Open(ctx, d)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rc.Close() }()
	if _, err := io.ReadAll(rc); !errors.Is(err, ErrDigestMismatch) {
		t.Fatalf("tampered blob: %v", err)
	}
}

func TestS3ErrorMapping(t *testing.T) {
	for _, test := range []struct {
		code    string
		writing bool
		want    error
	}{
		{"PreconditionFailed", true, ErrConflict}, {"ConditionalRequestConflict", true, ErrConflict},
		{"NoSuchKey", false, ErrNotFound}, {"NoSuchKey", true, ErrConflict},
		{"AccessDenied", false, nil}, {"NoSuchBucket", false, nil}, {"InternalError", true, nil},
	} {
		cause := minio.ErrorResponse{Code: test.code, Message: "test"}
		err := s3Error(cause, test.writing)
		if !errors.Is(err, cause) {
			t.Fatal("lost cause")
		}
		if test.want != nil && !errors.Is(err, test.want) {
			t.Fatalf("%s: %v", test.code, err)
		}
		if test.want == nil && (errors.Is(err, ErrConflict) || errors.Is(err, ErrNotFound)) {
			t.Fatalf("misclassified %s", test.code)
		}
	}
}

func TestS3BlobPutRepairsTruncatedBlob(t *testing.T) {
	st, raw := minis3Store(t)
	ctx := context.Background()
	d := digest.FromString("secret")
	key, _ := raw.blobKey(d)
	if _, err := raw.client.PutObject(ctx, raw.bucket, key, bytes.NewReader([]byte("sec")), 3, minio.PutObjectOptions{}); err != nil {
		t.Fatal(err)
	}
	if got := putBlob(t, st, "secret"); got != d {
		t.Fatalf("digest=%s", got)
	}
	rc, err := st.Blobs.Open(ctx, d)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rc.Close() }()
	if b, err := io.ReadAll(rc); err != nil || string(b) != "secret" {
		t.Fatalf("blob=%q %v", b, err)
	}
}
