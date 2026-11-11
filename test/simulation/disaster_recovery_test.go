package simulation

import (
	"fmt"
	"testing"

	"github.com/enbu-net/enbu/pkg/storage"
	"github.com/enbu-net/enbu/pkg/storage/storagetest"
)

func TestRecoveryProbeRejectsRecordedStorageWrites(t *testing.T) {
	t.Parallel()
	for _, method := range []string{"publish", "delete"} {
		t.Run(method, func(t *testing.T) {
			tape := NewTape(1, "recorded-write-probe")
			store := &Store{Store: storagetest.NewMemory(), Tape: tape}
			object := storagetest.Object(storage.KindState, storage.StateScope("fixture", "default"), "head", "payload")
			if err := store.Publish(t.Context(), object); err != nil {
				t.Fatal(err)
			}
			start := 0
			if method == "delete" {
				start = len(tape.Recording.Entries)
				if err := store.Delete(t.Context(), object.Kind, object.Scope, object.Rev); err != nil {
					t.Fatal(err)
				}
			}
			if err := requireReadOnlyStorage(tape.Recording.Entries[start:]); err == nil {
				t.Fatal("a real recorded storage write bypassed the read-only probe")
			}
			start = len(tape.Recording.Entries)
			if _, err := store.Discover(t.Context(), object.Kind, object.Scope); err != nil {
				t.Fatal(err)
			}
			if err := requireReadOnlyStorage(tape.Recording.Entries[start:]); err != nil {
				t.Fatalf("read-only storage calls were rejected: %v", err)
			}
		})
	}
}

func TestDisasterRecoverySmoke(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{"witness", "all-stale", "compacted", "compacted-no-record", "compacted-old-data"} {
		t.Run(mode, func(t *testing.T) {
			exercise(t, 113, Plan{Devices: 3, Scenario: "disaster-" + mode + "-cold"})
		})
	}
}

func TestDisasterRecoveryClocks(t *testing.T) {
	t.Parallel()
	exploration(t)
	for _, devices := range []int{2, 3, 8} {
		for _, profile := range []string{"", "frozen", "backward", "skewed"} {
			for _, mode := range []string{"witness", "all-stale", "compacted", "compacted-no-record", "compacted-old-data"} {
				for _, cache := range []string{"warm", "cold"} {
					t.Run(fmt.Sprintf("devices-%d/%s/%s/%s", devices, profile, mode, cache), func(t *testing.T) {
						t.Parallel()
						shardCase(t)
						exercise(t, 113, Plan{Devices: devices, Clock: profile, Scenario: "disaster-" + mode + "-" + cache})
					})
				}
			}
		}
	}
}
