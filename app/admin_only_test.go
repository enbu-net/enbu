package app

import (
	"testing"

	"github.com/enbu-net/enbu/pkg/apperr"
	"github.com/enbu-net/enbu/pkg/config"
	"github.com/enbu-net/enbu/pkg/storage"
)

// AUTH-3: deleting revisions is an admin's right. A member can neither purge
// an environment nor reclaim a deleted environment's revisions, and nothing is
// deleted when it tries.
func TestMemberCannotPurge(t *testing.T) {
	alice := newAlice(t)
	bob := approved(t, alice)
	if err := alice.CreateEnvironment("dev"); err != nil {
		t.Fatal(err)
	}
	if err := alice.AddSecret(bg, "dev", "D", "1"); err != nil {
		t.Fatal(err)
	}
	if err := alice.SwitchEnvironment("default"); err != nil {
		t.Fatal(err)
	}
	// Bob pulls the commit that names the environment.
	share := func() {
		t.Helper()
		cfg, err := config.LoadProjectFrom(alice.RepositoryDir)
		if err != nil {
			t.Fatal(err)
		}
		if err := config.SaveProjectTo(bob.RepositoryDir, cfg); err != nil {
			t.Fatal(err)
		}
	}
	share()
	var incarnation string
	envs, _ := alice.ListEnvironments()
	for _, e := range envs {
		if e.Name == "dev" {
			incarnation = e.Incarnation
		}
	}
	scope := storage.StateScope(mustWorkspace(t, alice), "secrets/"+incarnation)
	revisions := func() int {
		revs, err := alice.Storage.Discover(bg, storage.KindState, scope)
		if err != nil {
			t.Fatal(err)
		}
		return len(revs)
	}
	before := revisions()
	if before == 0 {
		t.Fatal("the environment has no revision to protect")
	}
	if _, err := bob.DeleteEnvironment(bg, "dev", true); !apperr.Is(err, apperr.CodeAccessDenied) {
		t.Fatalf("a member purged an environment: %v", err)
	}
	if got := revisions(); got != before {
		t.Fatalf("a refused purge deleted revisions: %d of %d left", got, before)
	}
	if _, err := alice.DeleteEnvironment(bg, "dev", false); err != nil {
		t.Fatal(err)
	}
	share()
	if _, err := bob.PurgeIncarnation(bg, incarnation); !apperr.Is(err, apperr.CodeAccessDenied) {
		t.Fatalf("a member reclaimed a deleted environment's revisions: %v", err)
	}
	if got := revisions(); got != before {
		t.Fatalf("a refused reclaim deleted revisions: %d of %d left", got, before)
	}
}
