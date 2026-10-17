package storage

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"sort"
	"strings"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"github.com/opencontainers/go-digest"
)

type s3 struct {
	client *minio.Client
	bucket string
	prefix string
}

// NewS3 stores each revision as one object under prefix/revisions.
func NewS3(client *minio.Client, bucket, prefix string) Store {
	return s3{client, bucket, prefix}
}

// NewS3Client connects to an S3-compatible endpoint using environment, shared
// AWS profile, or IAM credentials. An empty endpoint selects Amazon S3.
func NewS3Client(endpoint, region string, pathStyle bool) (*minio.Client, error) {
	if endpoint == "" {
		endpoint = "https://s3.amazonaws.com"
	}
	u, err := url.Parse(endpoint)
	if err != nil {
		return nil, err
	}
	if (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil ||
		(u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return nil, fmt.Errorf("invalid S3 endpoint %q", endpoint)
	}
	if region == "" {
		region = os.Getenv("AWS_REGION")
	}
	if region == "" {
		region = os.Getenv("AWS_DEFAULT_REGION")
	}
	lookup := minio.BucketLookupAuto
	if pathStyle {
		lookup = minio.BucketLookupPath
	}
	return minio.New(u.Host, &minio.Options{
		Secure:       u.Scheme == "https",
		Region:       region,
		BucketLookup: lookup,
		Creds: credentials.NewChainCredentials([]credentials.Provider{
			&credentials.EnvAWS{}, &credentials.FileAWSCredentials{}, &credentials.IAM{},
		}),
	})
}

func (s s3) base() string {
	p := strings.Trim(s.prefix, "/")
	if p == "" {
		return ""
	}
	return p + "/"
}

func (s s3) key(name string) string { return s.base() + "revisions/" + name }

func (s s3) Capabilities() Capabilities { return Capabilities{PhysicalDelete: true} }

// open returns an object for ranged reads and its size.
func (s s3) open(ctx context.Context, name string) (*minio.Object, int64, error) {
	obj, err := s.client.GetObject(ctx, s.bucket, s.key(name), minio.GetObjectOptions{})
	if err != nil {
		return nil, 0, s3Error(err)
	}
	info, err := obj.Stat()
	if err != nil {
		_ = obj.Close()
		return nil, 0, s3Error(err)
	}
	if info.Size > maxFrameBytes {
		_ = obj.Close()
		return nil, 0, ErrTooLarge
	}
	return obj, info.Size, nil
}

func (s s3) readAll(ctx context.Context, name string) ([]byte, error) {
	obj, size, err := s.open(ctx, name)
	if err != nil {
		return nil, err
	}
	defer func() { _ = obj.Close() }()
	data := make([]byte, size)
	if _, err := obj.ReadAt(data, 0); err != nil && !errors.Is(err, io.EOF) {
		return nil, s3Error(err)
	}
	return data, nil
}

func (s s3) Publish(ctx context.Context, o Object) error {
	if err := ValidateObject(o); err != nil {
		return err
	}
	name, err := Name(o.Kind, o.Scope, o.Rev)
	if err != nil {
		return err
	}
	data := frame(o)
	opts := minio.PutObjectOptions{ContentType: "application/octet-stream", DisableMultipart: true}
	opts.SetMatchETagExcept("*")
	_, err = s.client.PutObject(ctx, s.bucket, s.key(name), bytes.NewReader(data), int64(len(data)), opts)
	if err != nil && !isExists(err) {
		return s3Error(err)
	}
	if isExists(err) {
		// The name is taken. Names are content-derived, so it must hold exactly this object.
		got, err := s.readAll(ctx, name)
		if err != nil {
			return err
		}
		if !bytes.Equal(got, data) {
			return fmt.Errorf("%w: %s already holds different content", ErrCorrupt, name)
		}
		return nil
	}
	// Read back by name: the size and the head, without transferring the blobs.
	obj, size, err := s.open(ctx, name)
	if err != nil {
		return err
	}
	defer func() { _ = obj.Close() }()
	if size != int64(len(data)) {
		return fmt.Errorf("%w: %s has the wrong size after publishing", ErrCorrupt, name)
	}
	_, _, err = readHead(obj, size, o.Rev)
	return err
}

func (s s3) FetchHead(ctx context.Context, kind Kind, scope string, rev digest.Digest) ([]byte, error) {
	name, err := Name(kind, scope, rev)
	if err != nil {
		return nil, err
	}
	obj, size, err := s.open(ctx, name)
	if err != nil {
		return nil, err
	}
	defer func() { _ = obj.Close() }()
	head, _, err := readHead(obj, size, rev)
	return head, err
}

func (s s3) OpenBlob(ctx context.Context, kind Kind, scope string, rev digest.Digest, index int) (io.ReadCloser, error) {
	name, err := Name(kind, scope, rev)
	if err != nil {
		return nil, err
	}
	obj, size, err := s.open(ctx, name)
	if err != nil {
		return nil, err
	}
	_, layout, err := readHead(obj, size, rev)
	if err != nil {
		_ = obj.Close()
		return nil, err
	}
	section, err := blobSection(obj, layout, index)
	if err != nil {
		_ = obj.Close()
		return nil, err
	}
	return struct {
		io.Reader
		io.Closer
	}{section, obj}, nil
}

func (s s3) Discover(ctx context.Context, kind Kind, scope string) ([]digest.Digest, error) {
	prefix, err := namePrefix(kind, scope)
	if err != nil {
		return nil, err
	}
	base := s.key("")
	var revs []digest.Digest
	listCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	for entry := range s.client.ListObjects(listCtx, s.bucket, minio.ListObjectsOptions{Prefix: base + prefix, Recursive: true}) {
		if entry.Err != nil {
			return nil, s3Error(entry.Err)
		}
		if rev, ok := revFromName(prefix, strings.TrimPrefix(entry.Key, base)); ok {
			revs = append(revs, rev)
		}
	}
	sort.Slice(revs, func(i, j int) bool { return revs[i] < revs[j] })
	return revs, ctx.Err()
}

func (s s3) Delete(ctx context.Context, kind Kind, scope string, rev digest.Digest) error {
	name, err := Name(kind, scope, rev)
	if err != nil {
		return err
	}
	return s3Error(s.client.RemoveObject(ctx, s.bucket, s.key(name), minio.RemoveObjectOptions{}))
}

func isExists(err error) bool {
	var api minio.ErrorResponse
	return errors.As(err, &api) && (api.Code == "PreconditionFailed" || api.Code == "ConditionalRequestConflict")
}

func s3Error(err error) error {
	if err == nil {
		return nil
	}
	var api minio.ErrorResponse
	if errors.As(err, &api) && (api.Code == "NoSuchKey" || api.Code == "NotFound") {
		return fmt.Errorf("%w: %w", ErrNotFound, err)
	}
	return err
}
