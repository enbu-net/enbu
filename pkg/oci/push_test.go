package oci_test

import (
	"context"
	"strings"
	"testing"

	"github.com/enbu-net/enbu/pkg/oci"
)

func TestPush_OversizedPayloadRejectedBeforeRegistryAccess(t *testing.T) {
	data := make([]byte, 10*1024*1024+1)
	err := oci.Push(context.Background(), "not a valid OCI reference", "application/octet-stream", data, "token", nil)
	if err == nil {
		t.Fatal("expected error for oversized payload, got nil")
	}
	if !strings.HasPrefix(err.Error(), "artifact too large:") {
		t.Fatalf("expected oversized-payload error, got %v", err)
	}
}
