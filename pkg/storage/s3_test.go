package storage

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"reflect"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/smithy-go"
	"github.com/yashikota/minis3"
)

func minis3Store(t *testing.T) *S3 {
	t.Helper()
	server, err := minis3.Run()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close() })
	client := s3.New(s3.Options{Region: "us-east-1", Credentials: credentials.NewStaticCredentialsProvider("test", "test", ""), BaseEndpoint: aws.String("http://" + server.Addr()), UsePathStyle: true})
	if _, err := client.CreateBucket(context.Background(), &s3.CreateBucketInput{Bucket: aws.String("enbu-test")}); err != nil {
		t.Fatal(err)
	}
	return &S3{Client: client, Bucket: "enbu-test", Prefix: "workspace"}
}

func TestS3Minis3Contract(t *testing.T) { contract(t, minis3Store(t)) }

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
		if _, err := s.Client.PutObject(ctx, &s3.PutObjectInput{Bucket: aws.String(s.Bucket), Key: aws.String(s.key(fmt.Sprintf("key-%04d", i))), Body: bytes.NewReader([]byte("test"))}); err != nil {
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
	if _, err := s.Client.PutObject(context.Background(), &s3.PutObjectInput{Bucket: aws.String(s.Bucket), Key: aws.String(s.key("bad")), Body: bytes.NewReader([]byte("{}"))}); err != nil {
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
		cause := &smithy.GenericAPIError{Code: test.code, Message: "test"}
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
