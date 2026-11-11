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
			result, err := bob.InitializeRepository(bg, InitOptions{})
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

// The pins are written after the genesis is public. When that write fails,
// the retry recognises the genesis as this device's own founding, moves the
// repository pin and publishes nothing again.
func TestFoundingRecoversWhenThePinWriteFails(t *testing.T) {
	a := newAlice(t)
	pin := filepath.Join(a.checkpointDir(), "trust.json")
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
			blocked = true
		}
		return nil
	}})
	if _, err := a.InitializeRepository(bg, InitOptions{}); err == nil {
		t.Fatal("pin write did not fail")
	}
	genesis := genesisInConfig(t, a)
	if genesis == "" {
		t.Fatal("the published genesis was not recorded")
	}
	if err := os.RemoveAll(pin); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(pin+".backup", pin); err != nil {
		t.Fatal(err)
	}
	result, err := a.InitializeRepository(bg, InitOptions{})
	if err != nil || !result.Founded || result.ControlGenesis != genesis {
		t.Fatalf("recovery after a failed pin write: %+v %v", result, err)
	}
	if publishes != 1 {
		t.Fatalf("republished committed genesis %d times", publishes)
	}
	repo, err := a.trust().Repository(a.repositoryKey())
	if err != nil || repo != (wsp.Root{Workspace: cfg.WorkspaceID, Genesis: digest.Digest(genesis)}) {
		t.Fatalf("repository pin: %+v %v", repo, err)
	}
}

// Once founding pinned the workspace, signing its genesis is no longer a
// reason to move the repository pin: returning to it is a change of root.
func TestCompletedFoundingNeedsNoWriteAndCannotReroot(t *testing.T) {
	a := foundingApp(t, nil)
	real := a.Storage
	if _, err := a.InitializeRepository(bg, InitOptions{}); err != nil {
		t.Fatal(err)
	}
	original, err := config.LoadProjectFrom(a.RepositoryDir)
	if err != nil {
		t.Fatal(err)
	}
	writes := 0
	a.Storage = storagetest.Wrap(real, storagetest.Hooks{Publish: func(context.Context, storage.Store, storage.Object) error {
		writes++
		return errors.New("read-only credential")
	}})
	result, err := a.InitializeRepository(bg, InitOptions{})
	if err != nil || result.Founded || writes != 0 {
		t.Fatalf("completed init needs write: %+v %v writes=%d", result, err, writes)
	}
	// Found another workspace in the same checkout, which moves its pin.
	a.Storage = storagetest.NewMemory()
	nextConfig := config.NewProjectWithEnvironment("default")
	nextConfig.Storage = original.Storage
	if err := config.SaveProjectTo(a.RepositoryDir, nextConfig); err != nil {
		t.Fatal(err)
	}
	if _, err := a.InitializeRepository(bg, InitOptions{}); err != nil {
		t.Fatal(err)
	}
	newer, err := a.trust().Repository(a.repositoryKey())
	if err != nil || newer.Workspace != nextConfig.WorkspaceID {
		t.Fatalf("founding did not move the repository pin: %+v %v", newer, err)
	}
	if err := config.SaveProjectTo(a.RepositoryDir, original); err != nil {
		t.Fatal(err)
	}
	a.Storage = real
	if _, err := a.InitializeRepository(bg, InitOptions{}); !apperr.Is(err, apperr.CodeTrustRootChanged) {
		t.Fatalf("an earlier own founding rerooted the checkout: %v", err)
	}
	after, err := a.trust().Repository(a.repositoryKey())
	if err != nil || after != newer {
		t.Fatalf("repository pin changed: %+v %v", after, err)
	}
}
