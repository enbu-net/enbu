//go:build scenario

package test

import (
	"context"
	"testing"

	"github.com/enbu-net/enbu/pkg/oci"
)

const scenarioRegistryRef = "localhost:5000/test/enbu-scenario-registry"

func TestPushPullRoundTrip(t *testing.T) {
	ctx := context.Background()
	ref := scenarioRegistryRef + ":test-layer"
	data := []byte("hello scenario test")

	err := oci.Push(ctx, ref, "application/vnd.enbu.test.v1", data, "", nil)
	if err != nil {
		t.Fatalf("Push: %v", err)
	}

	got, err := oci.Pull(ctx, ref, "")
	if err != nil {
		t.Fatalf("Pull: %v", err)
	}

	if string(got) != string(data) {
		t.Fatalf("round-trip mismatch: got %q, want %q", got, data)
	}
}

func TestListTagsScenario(t *testing.T) {
	ctx := context.Background()
	ref := scenarioRegistryRef + ":tag-a"

	err := oci.Push(ctx, ref, "application/vnd.enbu.test.v1", []byte("a"), "", nil)
	if err != nil {
		t.Fatalf("Push tag-a: %v", err)
	}

	refB := scenarioRegistryRef + ":tag-b"
	err = oci.Push(ctx, refB, "application/vnd.enbu.test.v1", []byte("b"), "", nil)
	if err != nil {
		t.Fatalf("Push tag-b: %v", err)
	}

	tags, err := oci.ListTags(ctx, scenarioRegistryRef, "")
	if err != nil {
		t.Fatalf("ListTags: %v", err)
	}

	tagSet := make(map[string]bool)
	for _, tag := range tags {
		tagSet[tag] = true
	}

	if !tagSet["tag-a"] || !tagSet["tag-b"] {
		t.Fatalf("expected tags [tag-a, tag-b], got %v", tags)
	}
}

func TestGetDigestScenario(t *testing.T) {
	ctx := context.Background()
	ref := scenarioRegistryRef + ":digest-test"

	err := oci.Push(ctx, ref, "application/vnd.enbu.test.v1", []byte("digest data"), "", nil)
	if err != nil {
		t.Fatalf("Push: %v", err)
	}

	digest, err := oci.GetDigest(ctx, ref, "")
	if err != nil {
		t.Fatalf("GetDigest: %v", err)
	}

	if digest == "" {
		t.Fatal("expected non-empty digest")
	}
}
