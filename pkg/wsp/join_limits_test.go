package wsp

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/enbu-net/enbu/pkg/storage"
	"github.com/enbu-net/enbu/pkg/storage/storagetest"
	"github.com/opencontainers/go-digest"
)

// The work budget counts every listed/fetched object, not just requests whose
// signatures and workspace happen to verify. Otherwise junk bypasses the cap.
func TestJoinRequestFloodStopsBeforeFetching(t *testing.T) {
	refs := make([]digest.Digest, 10001)
	for i := range refs {
		refs[i] = digest.FromString(fmt.Sprintf("junk-%d", i))
	}
	reads := 0
	store := storagetest.Wrap(storagetest.NewMemory(), storagetest.Hooks{
		Discover: func(context.Context, storage.Store, storage.Kind, string) ([]digest.Digest, error) { return refs, nil },
		FetchHead: func(context.Context, storage.Store, storage.Kind, string, digest.Digest) ([]byte, error) {
			reads++
			return nil, storage.ErrNotFound
		},
	})
	if requests, err := ListJoinRequests(context.Background(), store, testWorkspace); !errors.Is(err, ErrInvalid) || len(requests) != 0 {
		t.Fatalf("request flood = %d requests, %v", len(requests), err)
	}
	if reads != 0 {
		t.Fatalf("request flood fetched %d objects before refusing the listing", reads)
	}
}

func TestInvalidRequestBytesStillConsumeTheReadBudget(t *testing.T) {
	refs := make([]digest.Digest, 40)
	for i := range refs {
		refs[i] = digest.FromString(fmt.Sprintf("large-junk-%d", i))
	}
	blob := bytes.Repeat([]byte("!"), 1<<20)
	reads := 0
	store := storagetest.Wrap(storagetest.NewMemory(), storagetest.Hooks{
		Discover: func(context.Context, storage.Store, storage.Kind, string) ([]digest.Digest, error) { return refs, nil },
		FetchHead: func(context.Context, storage.Store, storage.Kind, string, digest.Digest) ([]byte, error) {
			reads++
			return blob, nil
		},
	})
	if requests, err := ListJoinRequests(context.Background(), store, testWorkspace); !errors.Is(err, ErrInvalid) || len(requests) != 0 {
		t.Fatalf("invalid-byte flood = %d requests, %v", len(requests), err)
	}
	// 32 MiB is the aggregate budget. One fetched object can cross that budget,
	// but it must be rejected before parsing and no later object may be fetched.
	if reads != 33 {
		t.Fatalf("large invalid requests read %d MiB, want stop at 33", reads)
	}
}

func TestJoinRequestBudgetsPermitTheirExactBoundaries(t *testing.T) {
	for _, tc := range []struct {
		name        string
		count, size int
	}{{"reference-count", 10000, 0}, {"aggregate-bytes", 32, 1 << 20}} {
		t.Run(tc.name, func(t *testing.T) {
			refs := make([]digest.Digest, tc.count)
			for i := range refs {
				refs[i] = digest.FromString(fmt.Sprintf("boundary-%d", i))
			}
			blob := bytes.Repeat([]byte("!"), tc.size)
			reads := 0
			store := storagetest.Wrap(storagetest.NewMemory(), storagetest.Hooks{
				Discover: func(context.Context, storage.Store, storage.Kind, string) ([]digest.Digest, error) { return refs, nil },
				FetchHead: func(context.Context, storage.Store, storage.Kind, string, digest.Digest) ([]byte, error) {
					reads++
					return blob, nil
				},
			})
			if _, err := ListJoinRequests(context.Background(), store, testWorkspace); err != nil {
				t.Fatalf("budget boundary rejected: %v", err)
			}
			if reads != tc.count {
				t.Fatalf("boundary fetched %d objects, want %d", reads, tc.count)
			}
		})
	}
}
