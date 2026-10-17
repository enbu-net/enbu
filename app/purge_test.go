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

// Purging must not delete secrets for a deletion that will then be refused.
func TestDeleteEnvironmentPurgingChecksEverythingBeforeDeleting(t *testing.T) {
	alice := newAlice(t)
	// "default" is the current environment, which cannot be deleted.
	n, err := alice.DeleteEnvironmentPurging(bg, "default")
	if !apperr.Is(err, apperr.CodeInvalidArgument) || n != 0 {
		t.Fatalf("deleting the current environment: %d %v", n, err)
	}
	if left := revisionsOf(t, alice, "default"); len(left) == 0 {
		t.Fatal("secrets were deleted although the environment could not be")
	}
	if _, err := alice.DeleteEnvironmentPurging(bg, "missing"); !apperr.Is(err, apperr.CodeEnvironmentMissing) {
		t.Fatalf("deleting an environment that does not exist: %v", err)
	}

	// A backend that cannot delete, or a device that may not, also stops it first.
	if err := alice.CreateEnvironment("dev"); err != nil {
		t.Fatal(err)
	}
	if err := alice.AddSecret(bg, "dev", "D", "1"); err != nil {
		t.Fatal(err)
	}
	if err := alice.SwitchEnvironment("default"); err != nil {
		t.Fatal(err)
	}
	real := alice.Storage
	alice.Storage = noDelete{real}
	if _, err := alice.DeleteEnvironmentPurging(bg, "dev"); !apperr.Is(err, apperr.CodeInvalidArgument) {
		t.Fatalf("a backend that cannot delete: %v", err)
	}
	alice.Storage = real
	if envs, _ := alice.ListEnvironments(); len(envs) != 2 {
		t.Fatalf("the environment was removed anyway: %+v", envs)
	}
	if left := revisionsOf(t, alice, "dev"); len(left) == 0 {
		t.Fatal("secrets were deleted although the environment stayed")
	}

	n, err = alice.DeleteEnvironmentPurging(bg, "dev")
	if err != nil || n != 1 {
		t.Fatalf("deleting with purge: %d %v", n, err)
	}
	if envs, _ := alice.ListEnvironments(); len(envs) != 1 {
		t.Fatalf("environments = %+v", envs)
	}
}

// Deleting an environment without --purge forgets where its revisions are; they
// can still be reclaimed afterwards through the incarnation.
func TestPurgeIncarnationReclaimsWhatAPlainDeleteLeft(t *testing.T) {
	alice := newAlice(t)
	if err := alice.CreateEnvironment("dev"); err != nil {
		t.Fatal(err)
	}
	if err := alice.AddSecret(bg, "dev", "D", "1"); err != nil {
		t.Fatal(err)
	}
	envs, _ := alice.ListEnvironments()
	var incarnation string
	for _, e := range envs {
		if e.Name == "dev" {
			incarnation = e.Incarnation
		}
	}
	if incarnation == "" {
		t.Fatal("the environment has no incarnation to remember")
	}
	scope := storage.StateScope(mustWorkspace(t, alice), "secrets/"+incarnation)

	if _, err := alice.PurgeIncarnation(bg, incarnation); !apperr.Is(err, apperr.CodeInvalidArgument) {
		t.Fatalf("purging the lineage of a live environment: %v", err)
	}
	if err := alice.SwitchEnvironment("default"); err != nil {
		t.Fatal(err)
	}
	if err := alice.DeleteEnvironment("dev"); err != nil {
		t.Fatal(err)
	}
	if revs, _ := alice.Storage.Discover(bg, storage.KindState, scope); len(revs) != 1 {
		t.Fatalf("the plain delete should leave the revisions: %v", revs)
	}
	if _, err := alice.PurgeIncarnation(bg, "not-a-uuid"); !apperr.Is(err, apperr.CodeInvalidArgument) {
		t.Fatalf("a malformed incarnation: %v", err)
	}
	n, err := alice.PurgeIncarnation(bg, incarnation)
	if err != nil || n != 1 {
		t.Fatalf("purge by incarnation: %d %v", n, err)
	}
	if revs, _ := alice.Storage.Discover(bg, storage.KindState, scope); len(revs) != 0 {
		t.Fatalf("revisions left: %v", revs)
	}
}
