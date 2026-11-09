package app

import (
	"context"
	"testing"

	"github.com/enbu-net/enbu/pkg/apperr"
	"github.com/enbu-net/enbu/pkg/storage"
	"github.com/enbu-net/enbu/pkg/storage/storagetest"
	"github.com/enbu-net/enbu/pkg/wsp"
)

// TestMembersChangingOnEveryAttemptIsAConflict is ERR-1 (F5): when an admin
// changes the members right after every revision a write publishes, the
// write gives up with a conflict a person can act on (run it again), not an
// internal error.
func TestMembersChangingOnEveryAttemptIsAConflict(t *testing.T) {
	alice := newAlice(t)
	if err := alice.AddSecret(bg, "default", "FIRST", "value"); err != nil {
		t.Fatal(err)
	}
	base := alice.Storage
	changes := 0
	alice.Storage = storagetest.Wrap(base, storagetest.Hooks{
		Publish: func(ctx context.Context, next storage.Store, o storage.Object) error {
			if err := next.Publish(ctx, o); err != nil {
				return err
			}
			if o.Kind != storage.KindState {
				return nil
			}
			s, err := (&App{Storage: base, Identities: alice.Identities, CheckpointDir: t.TempDir(), RepositoryDir: alice.RepositoryDir}).openSession(ctx)
			if err != nil {
				return err
			}
			defer s.Close()
			extra := extraPrincipal(t)
			if _, err := wsp.UpdateControl(ctx, base, s.view, s.signer, func(c *wsp.Control) error {
				c.Principals = append(c.Principals, extra)
				return nil
			}); err != nil {
				return err
			}
			changes++
			return nil
		},
	})
	err := alice.AddSecret(bg, "default", "SECOND", "value")
	if err == nil {
		t.Fatalf("the write succeeded although the members changed after each of its %d revisions", changes)
	}
	if changes < maxRetries {
		t.Fatalf("the members changed only %d times; the test needs every attempt to see a change", changes)
	}
	if code := apperr.CodeOf(err); code != apperr.CodeConflict {
		t.Fatalf("members kept changing: code %s (%v), want %s", code, err, apperr.CodeConflict)
	}
}
