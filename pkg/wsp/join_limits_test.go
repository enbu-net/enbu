package wsp

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

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

func TestJoinRequestDiscoveryBudgetIsUntrusted(t *testing.T) {
	store := storagetest.Wrap(storagetest.NewMemory(), storagetest.Hooks{
		Discover: func(context.Context, storage.Store, storage.Kind, string) ([]digest.Digest, error) {
			return nil, storage.ErrDiscoveryLimit
		},
	})
	requests, err := ListJoinRequests(t.Context(), store, testWorkspace)
	if requests != nil || !errors.Is(err, ErrInvalid) || !errors.Is(err, storage.ErrDiscoveryLimit) {
		t.Fatalf("discovery limit lost its untrusted classification or cause: %v", err)
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
	actor := newActor(t, false)
	valid, err := NewJoinRequest(testWorkspace, actor.p.Recipient, time.Unix(1700000000, 0), actor.signer)
	if err != nil {
		t.Fatal(err)
	}
	validRev := digest.FromBytes(valid)
	for _, tc := range []struct {
		name        string
		count, size int
	}{{"reference-count", 10000, 0}, {"aggregate-bytes", 33, 1 << 20}} {
		t.Run(tc.name, func(t *testing.T) {
			refs := make([]digest.Digest, tc.count)
			for i := range refs {
				refs[i] = digest.FromString(fmt.Sprintf("boundary-%d", i))
			}
			refs[len(refs)-1] = validRev
			blob := bytes.Repeat([]byte("!"), tc.size)
			reads := 0
			store := storagetest.Wrap(storagetest.NewMemory(), storagetest.Hooks{
				Discover: func(context.Context, storage.Store, storage.Kind, string) ([]digest.Digest, error) { return refs, nil },
				FetchHead: func(context.Context, storage.Store, storage.Kind, string, digest.Digest) ([]byte, error) {
					reads++
					if reads == tc.count {
						return valid, nil
					}
					if tc.size != 0 && reads == tc.count-1 {
						return blob[:tc.size-len(valid)], nil
					}
					return blob, nil
				},
			})
			requests, err := ListJoinRequests(context.Background(), store, testWorkspace)
			if err != nil {
				t.Fatalf("budget boundary rejected: %v", err)
			}
			if len(requests) != 1 || requests[0].Rev != validRev || requests[0].DeviceID() != actor.p.ID || requests[0].Recipient != actor.p.Recipient {
				t.Fatal("exact budget boundary lost the final valid signed request")
			}
			if reads != tc.count {
				t.Fatalf("boundary fetched %d objects, want %d", reads, tc.count)
			}
		})
	}
}
