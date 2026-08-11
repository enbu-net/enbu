package desktop

import (
	"context"
	"errors"
	"testing"
)

func TestServiceRejectsUnknownSessionWithoutStartingRuntime(t *testing.T) {
	service := NewService("test")
	service.Startup(context.Background())
	if _, err := service.Snapshot("missing"); !errors.Is(err, ErrUnknownSession) {
		t.Fatalf("Snapshot = %v", err)
	}
	if service.GetAppVersion() != "test" {
		t.Fatal("version mismatch")
	}
}

func TestImportFormatIsFiniteAndDefaultsOpaqueMediaType(t *testing.T) {
	kind, payload, mediaType, err := importFormat("opaque", "")
	if err != nil || kind != "OpaqueImport" || payload != "content" || mediaType != "application/octet-stream" {
		t.Fatalf("importFormat(opaque) = %q, %q, %q, %v", kind, payload, mediaType, err)
	}
	if _, _, _, err := importFormat("executable", "application/wasm"); err == nil {
		t.Fatal("unregistered import format was accepted")
	}
}

func TestRandomUUIDProducesDistinctValidUUIDs(t *testing.T) {
	first, second, err := randomPair()
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("random UUID pair collided")
	}
	if err := first.Validate(); err != nil {
		t.Fatalf("first UUID is invalid: %v", err)
	}
	if err := second.Validate(); err != nil {
		t.Fatalf("second UUID is invalid: %v", err)
	}
}
