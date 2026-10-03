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
)

type S3 struct {
	Client *minio.Client
	Bucket string
	Prefix string
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

func (s *S3) Capabilities() Capabilities { return Capabilities{AtomicUpdates: true} }
func (s *S3) base() string {
	p := strings.Trim(s.Prefix, "/")
	if p == "" {
		return ""
	}
	return p + "/"
}
func (s *S3) key(key string) string { return s.base() + key + ".json" }

func (s *S3) Get(ctx context.Context, key string) (Object, Version, error) {
	if err := ValidateKey(key); err != nil {
		return Object{}, "", err
	}
	resp, err := s.Client.GetObject(ctx, s.Bucket, s.key(key), minio.GetObjectOptions{})
	if err != nil {
		return Object{}, "", s3Error(err, false)
	}
	defer func() { _ = resp.Close() }()
	b, err := io.ReadAll(io.LimitReader(resp, MaxEnvelopeBytes+1))
	if err != nil {
		return Object{}, "", s3Error(err, false)
	}
	info, err := resp.Stat()
	if err != nil {
		return Object{}, "", s3Error(err, false)
	}
	o, err := Decode(b)
	if err != nil {
		return Object{}, "", err
	}
	if info.ETag == "" {
		return Object{}, "", errors.New("S3 response missing ETag")
	}
	return o, Version(info.ETag), nil
}

func (s *S3) Put(ctx context.Context, key string, o Object, expected Version) error {
	if err := ValidateKey(key); err != nil {
		return err
	}
	b, err := Encode(o)
	if err != nil {
		return err
	}
	opts := minio.PutObjectOptions{ContentType: "application/vnd.enbu.storage.v1+json", DisableMultipart: true}
	if expected == "" {
		opts.SetMatchETagExcept("*")
	} else {
		opts.SetMatchETag(string(expected))
	}
	_, err = s.Client.PutObject(ctx, s.Bucket, s.key(key), bytes.NewReader(b), int64(len(b)), opts)
	return s3Error(err, true)
}

func (s *S3) List(ctx context.Context, prefix string) ([]string, error) {
	base := s.base()
	var keys []string
	listCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	for entry := range s.Client.ListObjects(listCtx, s.Bucket, minio.ListObjectsOptions{Prefix: base + prefix, Recursive: true}) {
		if entry.Err != nil {
			return nil, s3Error(entry.Err, false)
		}
		name := entry.Key
		if !strings.HasPrefix(name, base) || !strings.HasSuffix(name, ".json") {
			continue
		}
		key := strings.TrimSuffix(strings.TrimPrefix(name, base), ".json")
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
