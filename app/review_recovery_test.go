package app

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/enbu-net/enbu/pkg/apperr"
	"github.com/enbu-net/enbu/pkg/config"
	"github.com/enbu-net/enbu/pkg/storage"
	"github.com/enbu-net/enbu/pkg/storage/storagetest"
	"github.com/enbu-net/enbu/pkg/wsp"
	"github.com/opencontainers/go-digest"
)

func TestJoinRequestCleanupToleratesUnsupportedAndAlreadyDeleted(t *testing.T) {
	for _, failure := range []error{storage.ErrUnsupported, storage.ErrNotFound, errors.New("offline")} {
		t.Run(failure.Error(), func(t *testing.T) {
			alice := newAlice(t)
			bob := newDevice(t, alice)
			ws := mustWorkspace(t, bob)
			signer, _, _, err := bob.Identities.CreateSigner(ws)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = signer.Close() }()
			blob, err := wsp.NewJoinRequest(ws, mustRecipient(t, alice), time.Unix(100, 0), signer)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := wsp.PublishJoinRequest(bg, bob.Storage, blob); err != nil {
				t.Fatal(err)
			}
			calls := 0
			bob.Storage = storagetest.Wrap(bob.Storage, storagetest.Hooks{Delete: func(ctx context.Context, next storage.Store, kind storage.Kind, scope string, rev digest.Digest) error {
				calls++
				if errors.Is(failure, storage.ErrNotFound) {
					if err := next.Delete(ctx, kind, scope, rev); err != nil {
						return err
					}
				}
				return failure
			}})
			result, err := bob.InitializeRepository(bg)
			if calls != 1 {
				t.Fatalf("cleanup calls %d", calls)
			}
			if !errors.Is(failure, storage.ErrUnsupported) && !errors.Is(failure, storage.ErrNotFound) {
				if !errors.Is(err, failure) {
					t.Fatalf("transport error swallowed: %v", err)
				}
				return
			}
			if err != nil || !result.Pending {
				t.Fatalf("join blocked: %+v %v", result, err)
			}
			requests, err := wsp.ListJoinRequests(bg, bob.Storage, ws)
			if err != nil {
				t.Fatal(err)
			}
			want := 1
			if errors.Is(failure, storage.ErrUnsupported) {
				want = 2
			}
			if len(requests) != want {
				t.Fatalf("requests: %+v", requests)
			}
			found := false
			for _, request := range requests {
				if request.Recipient == result.PublicKey {
					found = true
				}
			}
			if !found {
				t.Fatal("new recipient request absent")
			}
		})
	}
}

func TestFoundingRecoversAfterOnlyWorkspacePinCommits(t *testing.T) {
	a := newAlice(t)
	matches, err := filepath.Glob(filepath.Join(a.checkpointDir(), "repo-*.json"))
	if err != nil || len(matches) != 1 {
		t.Fatalf("repository pin: %v %v", matches, err)
	}
	pin := matches[0]
	cfg := config.NewProjectWithEnvironment("default")
	if err := config.SaveProjectTo(a.RepositoryDir, cfg); err != nil {
		t.Fatal(err)
	}
	blocked := false
	publishes := 0
	a.Storage = storagetest.Wrap(storagetest.NewMemory(), storagetest.Hooks{Publish: func(ctx context.Context, next storage.Store, obj storage.Object) error {
		if err := next.Publish(ctx, obj); err != nil {
			return err
		}
		if obj.Kind == storage.KindControl && !blocked {
			publishes++
			if err := os.Rename(pin, pin+".backup"); err != nil {
				return err
			}
			if err := os.Mkdir(pin, 0700); err != nil {
				return err
			}
			if err := os.WriteFile(filepath.Join(pin, "block"), []byte("blocked"), 0600); err != nil {
				return err
			}
			blocked = true
		}
		return nil
	}})
	if _, err := a.InitializeRepository(bg); err == nil {
		t.Fatal("repository pin write did not fail")
	}
	genesis := genesisInConfig(t, a)
	pinned, err := a.trustRoot(cfg.WorkspaceID).Pinned()
	if err != nil || string(pinned.Genesis) != genesis {
		t.Fatalf("workspace pin did not commit: %+v %v", pinned, err)
	}
	if err := os.RemoveAll(pin); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(pin+".backup", pin); err != nil {
		t.Fatal(err)
	}
	result, err := a.InitializeRepository(bg)
	if err != nil || !result.Founded || result.ControlGenesis != genesis {
		t.Fatalf("partial-pin recovery: %+v %v", result, err)
	}
	if publishes != 1 {
		t.Fatalf("republished committed genesis %d times", publishes)
	}
}

func TestCompletedFoundingRetainedRecordNeedsNoWriteAndCannotReroot(t *testing.T) {
	var saved []byte
	var path string
	a := foundingApp(t, func(context.Context, []byte) error { return nil })
	real := storagetest.NewMemory()
	a.Storage = storagetest.Wrap(real, storagetest.Hooks{Publish: func(ctx context.Context, next storage.Store, obj storage.Object) error {
		if obj.Kind == storage.KindControl {
			var err error
			path = pendingGenesisForTest(t, a, string(obj.Rev))
			saved, err = os.ReadFile(path)
			if err != nil {
				return err
			}
		}
		return next.Publish(ctx, obj)
	}})
	if _, err := a.InitializeRepository(bg); err != nil {
		t.Fatal(err)
	}
	original, err := config.LoadProjectFrom(a.RepositoryDir)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, saved, 0600); err != nil {
		t.Fatal(err)
	}
	writes := 0
	a.Storage = storagetest.Wrap(real, storagetest.Hooks{Publish: func(context.Context, storage.Store, storage.Object) error {
		writes++
		return errors.New("read-only credential")
	}})
	result, err := a.InitializeRepository(bg)
	if err != nil || result.Founded || writes != 0 {
		t.Fatalf("completed init needs write: %+v %v writes=%d", result, err, writes)
	}
	// The same record must not authorize replacing a later repository pin.
	a.Storage = storagetest.NewMemory()
	nextConfig := config.NewProjectWithEnvironment("default")
	nextConfig.Storage = original.Storage
	if err := config.SaveProjectTo(a.RepositoryDir, nextConfig); err != nil {
		t.Fatal(err)
	}
	if _, err := a.InitializeRepository(bg); err != nil {
		t.Fatal(err)
	}
	newer, err := a.repositoryTrustRoot().Pinned()
	if err != nil {
		t.Fatal(err)
	}
	if err := config.SaveProjectTo(a.RepositoryDir, original); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, saved, 0600); err != nil {
		t.Fatal(err)
	}
	a.Storage = real
	if _, err := a.InitializeRepository(bg); !apperr.Is(err, apperr.CodeTrustRootChanged) {
		t.Fatalf("stale authorization rerooted: %v", err)
	}
	after, err := a.repositoryTrustRoot().Pinned()
	if err != nil || after != newer {
		t.Fatalf("repository pin changed: %+v %v", after, err)
	}
}
