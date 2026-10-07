package storage

import (
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
type s3Blobs struct{ s3 }
type s3Refs struct{ s3 }

// NewS3 stores blobs under prefix/blobs/sha256 and refs under prefix/refs.
func NewS3(client *minio.Client, bucket, prefix string) *Store {
	s := s3{client, bucket, prefix}
	return &Store{Blobs: s3Blobs{s}, Refs: s3Refs{s}}
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
func (s s3) blobKey(d digest.Digest) (string, error) {
	if err := ValidateDigest(d); err != nil {
		return "", err
	}
	return s.base() + "blobs/sha256/" + d.Encoded(), nil
}
func (s s3) refKey(name string) string { return s.base() + "refs/" + name }

func (s s3Blobs) Put(ctx context.Context, src io.Reader) (digest.Digest, error) {
	f, err := spool(ctx, src)
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	key, err := s.blobKey(f.Digest)
	if err != nil {
		return "", err
	}
	opts := minio.PutObjectOptions{ContentType: "application/octet-stream", DisableMultipart: true}
	opts.SetMatchETagExcept("*")
	_, err = s.client.PutObject(ctx, s.bucket, key, f, f.Size, opts)
	if err = s3Error(err, true); err == nil {
		return f.Digest, nil
	} else if !errors.Is(err, ErrConflict) {
		return "", err
	}
	// The blob already exists. Its content may be damaged, and f is known to match
	// the digest, so rewriting it unconditionally is safe and repairs it.
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return "", err
	}
	_, err = s.client.PutObject(ctx, s.bucket, key, f, f.Size, minio.PutObjectOptions{ContentType: "application/octet-stream", DisableMultipart: true})
	return f.Digest, s3Error(err, true)
}

func (s s3Blobs) Open(ctx context.Context, d digest.Digest) (io.ReadCloser, error) {
	key, err := s.blobKey(d)
	if err != nil {
		return nil, err
	}
	resp, err := s.client.GetObject(ctx, s.bucket, key, minio.GetObjectOptions{})
	if err != nil {
		return nil, s3Error(err, false)
	}
	if _, err := resp.Stat(); err != nil {
		_ = resp.Close()
		return nil, s3Error(err, false)
	}
	return newVerifyReader(resp, d), nil
}

func (s s3Refs) Get(ctx context.Context, name string) (digest.Digest, Version, error) {
	if err := ValidateKey(name); err != nil {
		return "", "", err
	}
	resp, err := s.client.GetObject(ctx, s.bucket, s.refKey(name), minio.GetObjectOptions{})
	if err != nil {
		return "", "", s3Error(err, false)
	}
	defer func() { _ = resp.Close() }()
	b, err := io.ReadAll(io.LimitReader(resp, 256))
	if err != nil {
		return "", "", s3Error(err, false)
	}
	info, err := resp.Stat()
	if err != nil {
		return "", "", s3Error(err, false)
	}
	if info.ETag == "" {
		return "", "", errors.New("S3 response missing ETag")
	}
	d, err := parseRef(b)
	return d, Version(info.ETag), err
}

func (s s3Refs) Put(ctx context.Context, name string, target digest.Digest, expected Version) error {
	if err := ValidateKey(name); err != nil {
		return err
	}
	if err := ValidateDigest(target); err != nil {
		return err
	}
	opts := minio.PutObjectOptions{ContentType: "text/plain", DisableMultipart: true}
	if expected == "" {
		opts.SetMatchETagExcept("*")
	} else {
		opts.SetMatchETag(string(expected))
	}
	_, err := s.client.PutObject(ctx, s.bucket, s.refKey(name), strings.NewReader(string(target)), int64(len(target)), opts)
	return s3Error(err, true)
}

func (s s3Refs) List(ctx context.Context, prefix string) ([]string, error) {
	base := s.base() + "refs/"
	var keys []string
	listCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	for entry := range s.client.ListObjects(listCtx, s.bucket, minio.ListObjectsOptions{Prefix: base + prefix, Recursive: true}) {
		if entry.Err != nil {
			return nil, s3Error(entry.Err, false)
		}
		key := strings.TrimPrefix(entry.Key, base)
		if err := ValidateKey(key); err != nil {
			return nil, err
		}
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys, ctx.Err()
}

func s3Error(err error, writing bool) error {
	if err == nil {
		return nil
	}
	var api minio.ErrorResponse
	if errors.As(err, &api) {
		switch api.Code {
		case "PreconditionFailed", "ConditionalRequestConflict":
			return fmt.Errorf("%w: %w", ErrConflict, err)
		case "NoSuchKey", "NotFound":
			if writing {
				return fmt.Errorf("%w: %w", ErrConflict, err)
			}
			return fmt.Errorf("%w: %w", ErrNotFound, err)
		}
	}
	return err
}
