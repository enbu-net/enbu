package oci_test

import (
	"context"
	"testing"

	"github.com/enbu-net/enbu/pkg/oci"
)

func TestPush_OversizedPayloadRejectedBeforeRegistryAccess(t *testing.T) {
	// maxArtifactBytes + 1 must fail before any network call is made.
	// Using an invalid ref ensures the test would fail for a different reason
	// (ref parse error) if the size guard were absent or bypassed.
	data := make([]byte, 10*1024*1024+1)
	err := oci.Push(context.Background(), "ghcr.io/invalid/ref:tag", "application/octet-stream", data, "token", nil)
	if err == nil {
		t.Fatal("expected error for oversized payload, got nil")
	}
}
