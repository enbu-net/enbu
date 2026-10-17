package app

import (
	"testing"

	"github.com/enbu-net/enbu/pkg/apperr"
	"github.com/enbu-net/enbu/pkg/storage"
)

// noDelete is a backend that cannot delete, like a registry without a provider API.
type noDelete struct{ storage.Store }

func (noDelete) Capabilities() storage.Capabilities { return storage.Capabilities{} }

func TestPurgeEnvironmentDeletesOnlyThatEnvironmentsRevisions(t *testing.T) {
	alice := newAlice(t)
	if err := alice.CreateEnvironment("dev"); err != nil {
		t.Fatal(err)
	}
	if err := alice.AddSecret(bg, "dev", "D", "1"); err != nil {
		t.Fatal(err)
	}
	if err := alice.EditSecret(bg, "dev", "D", "2"); err != nil {
		t.Fatal(err)
	}
	n, err := alice.PurgeEnvironment(bg, "dev")
	if err != nil || n != 2 {
		t.Fatalf("purged %d: %v", n, err)
	}
	if left := revisionsOf(t, alice, "dev"); len(left) != 0 {
		t.Fatalf("revisions left: %v", left)
	}
	if got := listOK(t, alice); got["KEY"] != "v1" {
		t.Fatalf("another environment was touched: %v", got)
	}
}

func TestPurgeEnvironmentNeedsAnAdminAndABackendThatCanDelete(t *testing.T) {
	alice := newAlice(t)
	bob := approved(t, alice)
	if _, err := bob.PurgeEnvironment(bg, "default"); !apperr.Is(err, apperr.CodeAccessDenied) {
		t.Fatalf("a member deleted revisions: %v", err)
	}
	if left := revisionsOf(t, alice, "default"); len(left) == 0 {
		t.Fatal("revisions were deleted anyway")
	}
	alice.Storage = noDelete{alice.Storage}
	if _, err := alice.PurgeEnvironment(bg, "default"); !apperr.Is(err, apperr.CodeInvalidArgument) {
		t.Fatalf("a backend that cannot delete: %v", err)
	}
}
