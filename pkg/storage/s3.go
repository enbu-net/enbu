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

func (s s3) read(ctx context.Context, name string) ([]byte, error) {
	resp, err := s.client.GetObject(ctx, s.bucket, s.key(name), minio.GetObjectOptions{})
	if err != nil {
		return nil, s3Error(err)
	}
	defer func() { _ = resp.Close() }()
	data, err := io.ReadAll(io.LimitReader(resp, maxFrameBytes+1))
	if err != nil {
		return nil, s3Error(err)
	}
	if len(data) > maxFrameBytes {
		return nil, ErrTooLarge
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
	// Read back by name. An existing object must be identical: names are content-derived.
	got, err := s.read(ctx, name)
	if err != nil {
		return err
	}
	if !bytes.Equal(got, data) {
		return fmt.Errorf("%w: %s already holds different content", ErrCorrupt, name)
	}
	return nil
}

func (s s3) Fetch(ctx context.Context, kind Kind, scope string, rev digest.Digest) (Object, error) {
	name, err := Name(kind, scope, rev)
	if err != nil {
		return Object{}, err
	}
	data, err := s.read(ctx, name)
	if err != nil {
		return Object{}, err
	}
	return unframe(kind, scope, rev, data)
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
