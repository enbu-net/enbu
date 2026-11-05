package app

import (
	"context"
	"testing"

	"github.com/enbu-net/enbu/pkg/storage"
	"github.com/enbu-net/enbu/pkg/storage/storagetest"
	"github.com/enbu-net/enbu/pkg/wsp"
)

func TestPublishedAddSurvivesMembershipRetry(t *testing.T) {
	for _, laterWrite := range []bool{false, true} {
		name := "own-publication"
		if laterWrite {
			name = "later-writer"
		}
		t.Run(name, func(t *testing.T) {
			alice := newAlice(t)
			bob := approved(t, alice)
			base := alice.Storage
			extra := extraPrincipal(t)
			moved := false
			alice.Storage = storagetest.Wrap(base, storagetest.Hooks{Publish: func(ctx context.Context, next storage.Store, obj storage.Object) error {
				if err := next.Publish(ctx, obj); err != nil {
					return err
				}
				if obj.Kind != storage.KindState || moved {
					return nil
				}
				moved = true
				observer := &App{Storage: base, Identities: alice.Identities, CheckpointDir: t.TempDir(), RepositoryDir: alice.RepositoryDir}
				s, err := observer.openSession(ctx)
				if err != nil {
					return err
				}
				defer s.Close()
				if _, err := wsp.UpdateControl(ctx, base, s.view, s.signer, func(c *wsp.Control) error { c.Principals = append(c.Principals, extra); return nil }); err != nil {
					return err
				}
				if laterWrite {
					return bob.EditSecret(ctx, "default", "NEW", "later")
				}
				return nil
			}})
			if err := alice.AddSecret(bg, "default", "NEW", "value"); err != nil {
				t.Fatalf("published add became a duplicate: %v", err)
			}
			got, err := alice.ListSecrets(bg, "default")
			want := "value"
			if laterWrite {
				want = "later"
			}
			if err != nil || !moved || got["NEW"] != want || got["KEY"] != "v1" {
				t.Fatalf("retry changed committed data: got %v want NEW=%s moved=%t err=%v", got, want, moved, err)
			}
		})
	}
}
