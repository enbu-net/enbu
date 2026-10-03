package storage

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"github.com/yashikota/minis3"
)

func minis3Store(t *testing.T) *S3 {
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
	return &S3{Client: client, Bucket: "enbu-test", Prefix: "workspace"}
}

func TestS3Minis3Contract(t *testing.T) { contract(t, minis3Store(t)) }

func TestS3ListCanceled(t *testing.T) {
	s := minis3Store(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.List(ctx, ""); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled list: %v", err)
	}
}

func TestS3LargeConditionalWrite(t *testing.T) {
	s := minis3Store(t)
	ctx := context.Background()
	o := Object{MediaType: "application/test", Data: bytes.Repeat([]byte("x"), MaxPayloadBytes)}
	if err := s.Put(ctx, "large", o, ""); err != nil {
		t.Fatal(err)
	}
	got, version, err := s.Get(ctx, "large")
	if err != nil || !bytes.Equal(got.Data, o.Data) || version == "" {
		t.Fatalf("large object round trip: version=%q, err=%v", version, err)
	}
	if err := s.Put(ctx, "large", o, "stale"); !errors.Is(err, ErrConflict) {
		t.Fatalf("large stale write: %v", err)
	}
	o.Data[0] = 'y'
	if err := s.Put(ctx, "large", o, version); err != nil {
		t.Fatal(err)
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
			body, err := Encode(Object{MediaType: "application/test", Data: []byte("secret")})
			if err != nil {
				t.Fatal(err)
			}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet || r.URL.Path != "/enbu-test/workspace/object.json" {
					t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
				}
				if !strings.Contains(r.Header.Get("Authorization"), "Credential=test-key/") ||
					!strings.Contains(r.Header.Get("Authorization"), "/test-region/s3/aws4_request") ||
					r.Header.Get("X-Amz-Security-Token") != "test-token" {
					t.Error("request did not use the selected credentials and region")
				}
				w.Header().Set("ETag", "\"test-etag\"")
				w.Header().Set("Last-Modified", "Mon, 02 Jan 2006 15:04:05 GMT")
				_, _ = w.Write(body)
			}))
			t.Cleanup(server.Close)
			client, err := NewS3Client(server.URL, "", true)
			if err != nil {
				t.Fatal(err)
			}
			store := &S3{Client: client, Bucket: "enbu-test", Prefix: "workspace"}
			got, version, err := store.Get(context.Background(), "object")
			if err != nil || string(got.Data) != "secret" || version != "test-etag" {
				t.Fatalf("authenticated read: version=%q, err=%v", version, err)
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
	s := minis3Store(t)
	s.Prefix = ""
	if got := s.key("object"); got != "object.json" {
		t.Fatalf("bucket root key = %q", got)
	}
	contract(t, s)
}

func TestS3Minis3PrefixAndPagination(t *testing.T) {
	s := minis3Store(t)
	ctx := context.Background()
	for i := range 1003 {
		if _, err := s.Client.PutObject(ctx, s.Bucket, s.key(fmt.Sprintf("key-%04d", i)), bytes.NewReader([]byte("test")), 4, minio.PutObjectOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	other := *s
	other.Prefix = "workspace-other"
	if err := other.Put(ctx, "foreign", Object{MediaType: "application/test", Data: []byte("foreign")}, ""); err != nil {
		t.Fatal(err)
	}
	keys, err := s.List(ctx, "key-")
	if err != nil || len(keys) != 1003 {
		t.Fatalf("pagination=%d %v", len(keys), err)
	}
	keys, err = other.List(ctx, "")
	if err != nil || !reflect.DeepEqual(keys, []string{"foreign"}) {
		t.Fatalf("prefix=%v %v", keys, err)
	}
}

func TestS3Minis3Corruption(t *testing.T) {
	s := minis3Store(t)
	if _, err := s.Client.PutObject(context.Background(), s.Bucket, s.key("bad"), bytes.NewReader([]byte("{}")), 2, minio.PutObjectOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Get(context.Background(), "bad"); err == nil || errors.Is(err, ErrNotFound) {
		t.Fatalf("corruption=%v", err)
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
