package storage

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/smithy-go"
)

type S3 struct {
	Client *s3.Client
	Bucket string
	Prefix string
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
	resp, err := s.Client.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(s.Bucket), Key: aws.String(s.key(key))})
	if err != nil {
		return Object{}, "", s3Error(err, false)
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(io.LimitReader(resp.Body, MaxEnvelopeBytes+1))
	if err != nil {
		return Object{}, "", err
	}
	o, err := Decode(b)
	if err != nil {
		return Object{}, "", err
	}
	if resp.ETag == nil || *resp.ETag == "" {
		return Object{}, "", errors.New("S3 response missing ETag")
	}
	return o, Version(*resp.ETag), nil
}

func (s *S3) Put(ctx context.Context, key string, o Object, expected Version) error {
	if err := ValidateKey(key); err != nil {
		return err
	}
	b, err := Encode(o)
	if err != nil {
		return err
	}
	in := &s3.PutObjectInput{Bucket: aws.String(s.Bucket), Key: aws.String(s.key(key)), Body: bytes.NewReader(b), ContentType: aws.String("application/vnd.enbu.storage.v1+json")}
	if expected == "" {
		in.IfNoneMatch = aws.String("*")
	} else {
		in.IfMatch = aws.String(string(expected))
	}
	_, err = s.Client.PutObject(ctx, in)
	return s3Error(err, true)
}

func (s *S3) List(ctx context.Context, prefix string) ([]string, error) {
	base := s.base()
	p := s3.NewListObjectsV2Paginator(s.Client, &s3.ListObjectsV2Input{Bucket: aws.String(s.Bucket), Prefix: aws.String(base + prefix)})
	var keys []string
	for p.HasMorePages() {
		page, err := p.NextPage(ctx)
		if err != nil {
			return nil, s3Error(err, false)
		}
		for _, entry := range page.Contents {
			name := aws.ToString(entry.Key)
			if !strings.HasPrefix(name, base) || !strings.HasSuffix(name, ".json") {
				continue
			}
			key := strings.TrimSuffix(strings.TrimPrefix(name, base), ".json")
			if err := ValidateKey(key); err != nil {
				return nil, err
			}
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	return keys, nil
}

func s3Error(err error, writing bool) error {
	if err == nil {
		return nil
	}
	var api smithy.APIError
	if errors.As(err, &api) {
		switch api.ErrorCode() {
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
