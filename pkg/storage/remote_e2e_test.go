//go:build storagee2e

package storage

import (
	"context"
	"os"
	"testing"
	"uuid"

	"github.com/minio/minio-go/v7"
)

func TestRemoteStorage(t *testing.T) {
	t.Run("OCI", func(t *testing.T) {
		ref := os.Getenv("ENBU_TEST_OCI_REF")
		if ref == "" {
			t.Skip("ENBU_TEST_OCI_REF not set")
		}
		st, err := NewOCI(ref+"/"+uuid.NewV4().String(), nil, true)
		if err != nil {
			t.Fatal(err)
		}
		contract(t, st)
	})
	t.Run("S3", func(t *testing.T) {
		bucket := os.Getenv("ENBU_TEST_S3_BUCKET")
		if bucket == "" {
			t.Skip("ENBU_TEST_S3_BUCKET not set")
		}
		client, err := NewS3Client(os.Getenv("ENBU_TEST_S3_ENDPOINT"), "", true)
		if err != nil {
			t.Fatal(err)
		}
		if os.Getenv("ENBU_TEST_CREATE_BUCKET") == "1" {
			if err := client.MakeBucket(context.Background(), bucket, minio.MakeBucketOptions{}); err != nil {
				t.Fatal(err)
			}
		}
		prefix := "storage-contract/" + uuid.NewV4().String()
		st := NewS3(client, bucket, prefix)
		t.Cleanup(func() {
			for obj := range client.ListObjects(context.Background(), bucket, minio.ListObjectsOptions{Prefix: prefix + "/", Recursive: true}) {
				if obj.Err != nil {
					t.Error(obj.Err)
					return
				}
				if err := client.RemoveObject(context.Background(), bucket, obj.Key, minio.RemoveObjectOptions{}); err != nil {
					t.Error(err)
				}
			}
		})
		contract(t, st)
		atomicContract(t, st)
	})
}
