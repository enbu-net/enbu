package app

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"testing"

	"github.com/enbu-net/enbu/pkg/apperr"
	"github.com/enbu-net/enbu/pkg/storage"
	"github.com/enbu-net/enbu/pkg/storage/storagetest"
	"github.com/enbu-net/enbu/pkg/wsp"
	"github.com/opencontainers/go-digest"
)

func TestRequestFloodPreservesMembershipAndAllowsRecovery(t *testing.T) {
	alice := newAlice(t)
	bob := newDevice(t, alice)
	pending := requestJoin(t, bob)
	before, err := alice.ListMembers(bg)
	if err != nil {
		t.Fatal(err)
	}
	refs := make([]digest.Digest, 10001)
	for i := range refs {
		refs[i] = digest.FromString(fmt.Sprintf("request-flood-%d", i))
	}
	active, reads := true, 0
	backend := alice.Storage
	attack := storagetest.Wrap(backend, storagetest.Hooks{
		Discover: func(ctx context.Context, next storage.Store, kind storage.Kind, scope string) ([]digest.Digest, error) {
			if active && kind == storage.KindRequest {
				return refs, nil
			}
			return next.Discover(ctx, kind, scope)
		},
		FetchHead: func(ctx context.Context, next storage.Store, kind storage.Kind, scope string, rev digest.Digest) ([]byte, error) {
			if active && kind == storage.KindRequest {
				reads++
			}
			return next.FetchHead(ctx, kind, scope, rev)
		},
	})
	alice.Storage, bob.Storage = attack, attack
	for _, run := range []func() error{
		func() error { _, err := alice.ListJoinRequests(bg); return err },
		func() error { return alice.ApproveMember(bg, pending.DeviceID) },
		func() error { _, err := bob.InitializeRepository(bg); return err },
	} {
		err := run()
		if !apperr.Is(err, apperr.CodeUntrusted) || !errors.Is(err, wsp.ErrInvalid) {
			t.Fatalf("request flood lost verification classification/cause: %v", err)
		}
	}
	if reads != 0 {
		t.Fatalf("request flood fetched %d objects", reads)
	}
	after, err := alice.ListMembers(bg)
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatalf("flood changed membership: %v", err)
	}
	if err := alice.AddSecret(bg, "default", "DURING_FLOOD", "kept"); err != nil {
		t.Fatal(err)
	}
	if _, err := bob.ListSecrets(bg, "default"); !apperr.Is(err, apperr.CodeNotMember) {
		t.Fatalf("flood implicitly approved pending device: %v", err)
	}
	active = false
	if err := alice.ApproveMember(bg, pending.DeviceID); err != nil {
		t.Fatal(err)
	}
	mustRead(t, bob, "DURING_FLOOD", "kept")
}
