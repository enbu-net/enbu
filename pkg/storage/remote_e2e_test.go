//go:build storagee2e

package storage

import (
	"context"
	"os"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/google/uuid"
)

func TestRemoteStorage(t *testing.T) {
	t.Run("OCI", func(t *testing.T) {
		ref := os.Getenv("ENBU_TEST_OCI_REF")
		if ref == "" {
			t.Skip("ENBU_TEST_OCI_REF not set")
		}
		st, err := NewOCI(ref+"/"+uuid.NewString(), nil, true)
		if err != nil {
			t.Fatal(err)
		}
		contract(t, st)
		if st.Capabilities().AtomicUpdates {
			t.Fatal("OCI must report best-effort updates")
		}
	})
	t.Run("S3", func(t *testing.T) {
		bucket := os.Getenv("ENBU_TEST_S3_BUCKET")
		if bucket == "" {
			t.Skip("ENBU_TEST_S3_BUCKET not set")
		}
		cfg, err := awsconfig.LoadDefaultConfig(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		client := s3.NewFromConfig(cfg, func(o *s3.Options) {
			if ep := os.Getenv("ENBU_TEST_S3_ENDPOINT"); ep != "" {
				o.BaseEndpoint = aws.String(ep)
				o.UsePathStyle = true
			}
		})
		if os.Getenv("ENBU_TEST_CREATE_BUCKET") == "1" {
			if _, err := client.CreateBucket(context.Background(), &s3.CreateBucketInput{Bucket: aws.String(bucket)}); err != nil {
				t.Fatal(err)
			}
		}
		st := &S3{Client: client, Bucket: bucket, Prefix: "storage-contract/" + uuid.NewString()}
		t.Cleanup(func() {
			keys, err := st.List(context.Background(), "")
			if err != nil {
				t.Error(err)
				return
			}
			for _, key := range keys {
				if _, err := client.DeleteObject(context.Background(), &s3.DeleteObjectInput{Bucket: aws.String(bucket), Key: aws.String(st.key(key))}); err != nil {
					t.Error(err)
				}
			}
		})
		contract(t, st)
		atomicContract(t, st)
	})
}
