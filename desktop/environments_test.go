package desktop

import (
	"testing"

	"github.com/enbu-net/enbu/pkg/apperr"
)

// Deleting without purge keeps the revisions and names the incarnation that
// PurgeIncarnation deletes them by later, as `enbu switch --delete` prints it.
func TestDeleteEnvironmentKeepsRevisionsUntilPurged(t *testing.T) {
	f := newMembersFixture(t)
	if err := f.alice.ApproveMember(f.bobDevice); err != nil {
		t.Fatal(err)
	}
	if err := f.alice.CreateEnvironment("staging"); err != nil {
		t.Fatal(err)
	}
	if err := f.alice.AddSecret("staging", "KEY", "v1"); err != nil {
		t.Fatal(err)
	}
	if err := f.alice.SwitchEnvironment("default"); err != nil {
		t.Fatal(err)
	}
	deleted, err := f.alice.DeleteEnvironment("staging", false)
	if err != nil || deleted.Purged != 0 || deleted.Incarnation == "" {
		t.Fatalf("delete: %+v %v", deleted, err)
	}
	if envs, _ := f.alice.ListEnvironments(); len(envs) != 1 {
		t.Fatalf("environments after delete: %+v", envs)
	}
	if _, err := f.bob.PurgeIncarnation(deleted.Incarnation); !apperr.Is(err, apperr.CodeAccessDenied) {
		t.Fatalf("a non-admin purged: %v", err)
	}
	purged, err := f.alice.PurgeIncarnation(deleted.Incarnation)
	if err != nil || purged != 1 {
		t.Fatalf("purge: %d %v", purged, err)
	}
}

func TestDeleteEnvironmentCanPurgeRevisions(t *testing.T) {
	f := newMembersFixture(t)
	if err := f.alice.CreateEnvironment("staging"); err != nil {
		t.Fatal(err)
	}
	if err := f.alice.AddSecret("staging", "KEY", "v1"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.alice.DeleteEnvironment("staging", true); !apperr.Is(err, apperr.CodeInvalidArgument) {
		t.Fatalf("deleted the current environment: %v", err)
	}
	if err := f.alice.SwitchEnvironment("default"); err != nil {
		t.Fatal(err)
	}
	deleted, err := f.alice.DeleteEnvironment("staging", true)
	if err != nil || deleted.Purged != 1 || deleted.Incarnation != "" {
		t.Fatalf("delete: %+v %v", deleted, err)
	}
}
