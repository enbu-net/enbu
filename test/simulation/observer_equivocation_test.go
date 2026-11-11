package simulation

import (
	"fmt"
	"testing"

	"github.com/enbu-net/enbu/pkg/storage"
	"github.com/enbu-net/enbu/pkg/storage/storagetest"
)

func TestObserverEquivocationSmoke(t *testing.T) {
	for _, mode := range []string{"disjoint", "conflict"} {
		t.Run(mode, func(t *testing.T) {
			shardCase(t)
			exercise(t, 353, Plan{Devices: 3, Scenario: "observer-state-" + mode + "-cold"})
		})
	}
}

func TestObserverEquivocationClocks(t *testing.T) {
	exploration(t)
	for _, devices := range []int{3, 4, 8} {
		for _, clock := range []string{"", "frozen", "backward", "skewed"} {
			for _, mode := range []string{"disjoint", "conflict"} {
				for _, cache := range []string{"warm", "cold"} {
					t.Run(fmt.Sprintf("devices-%d/%s/%s/%s", devices, clock, mode, cache), func(t *testing.T) {
						shardCase(t)
						exercise(t, 353, Plan{Devices: devices, Clock: clock, Scenario: "observer-state-" + mode + "-" + cache})
					})
				}
			}
		}
	}
}

func TestMetadataOnlyProbeRejectsRecordedPayloadReads(t *testing.T) {
	tape := NewTape(353, "metadata-only-probe")
	store := &Store{Store: storagetest.NewMemory(), Tape: tape}
	object := storagetest.Object(storage.KindState, storage.StateScope("fixture", "default"), "head", "payload")
	if err := store.Publish(t.Context(), object); err != nil {
		t.Fatal(err)
	}
	start := len(tape.Recording.Entries)
	if _, err := store.Discover(t.Context(), object.Kind, object.Scope); err != nil {
		t.Fatal(err)
	}
	if _, err := store.FetchHead(t.Context(), object.Kind, object.Scope, object.Rev); err != nil {
		t.Fatal(err)
	}
	if err := requireMetadataOnlyStorage(tape.Recording.Entries[start:]); err != nil {
		t.Fatalf("metadata-only requests rejected: %v", err)
	}
	start = len(tape.Recording.Entries)
	reader, err := store.OpenPayload(t.Context(), object.Kind, object.Scope, object.Rev)
	if err != nil {
		t.Fatal(err)
	}
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
	entries := tape.Recording.Entries[start:]
	if err := requireReadOnlyStorage(entries); err != nil {
		t.Fatalf("fixture did not produce a valid read-only recording: %v", err)
	}
	if err := requireMetadataOnlyStorage(entries); err == nil {
		t.Fatal("an actual recorded payload read bypassed the metadata-only oracle")
	}
}
