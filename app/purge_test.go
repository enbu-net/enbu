package app

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/enbu-net/enbu/pkg/apperr"
	"github.com/enbu-net/enbu/pkg/config"
	"github.com/enbu-net/enbu/pkg/storage"
	"github.com/opencontainers/go-digest"
)

func TestPurgeRefusesAliasedResource(t *testing.T) {
	alice := newAlice(t)
	cfg, err := alice.loadProject()
	if err != nil {
		t.Fatal(err)
	}
	for _, inc := range []string{cfg.Environments["default"].Incarnation, "default"} {
		cfg.Environments["default"] = config.EnvironmentConfig{Output: ".env", Incarnation: inc}
		if inc == "default" {
			cfg.Environments["default"] = config.EnvironmentConfig{Output: ".env"}
			delete(cfg.Environments, "scratch")
			if err := config.SaveProjectTo(alice.RepositoryDir, cfg); err != nil {
				t.Fatal(err)
			}
			if err := alice.AddSecret(bg, "default", "LEGACY", "keep"); err != nil {
				t.Fatal(err)
			}
		}
		cfg.Environments["scratch"] = config.EnvironmentConfig{Output: "scratch.env", Incarnation: inc}
		content, err := config.MarshalProject(cfg)
		if err != nil {
			t.Fatal(err)
		}
		previous, err := alice.ReadConfig()
		if err != nil {
			t.Fatal(err)
		}
		if err := alice.WriteConfig(string(content), previous); !apperr.Is(err, apperr.CodeConfigResourceCollision) {
			t.Fatalf("saving aliased configuration: %v", err)
		}
		// An older enbu or a text editor could already have written the file.
		if err := os.WriteFile(filepath.Join(alice.RepositoryDir, "enbu.toml"), content, 0o600); err != nil {
			t.Fatal(err)
		}
		if result, err := alice.DeleteEnvironment(bg, "scratch", true); err == nil || result.Purged != 0 {
			t.Fatalf("purging aliased revisions: %+v %v", result, err)
		}
		scope := storage.StateScope(cfg.WorkspaceID, cfg.Resource("default"))
		if left, err := alice.Storage.Discover(bg, storage.KindState, scope); err != nil || len(left) == 0 {
			t.Fatalf("original revisions missing for %s: %v %v", scope, left, err)
		}
	}
}

func TestRepairAliasedConfigRequiresAnExistingDefault(t *testing.T) {
	a := newAlice(t)
	cfg, err := a.loadProject()
	if err != nil {
		t.Fatal(err)
	}
	cfg.DefaultEnv = "scratch"
	cfg.Environments["scratch"] = config.EnvironmentConfig{
		Output: "scratch.env", Incarnation: cfg.Environments["default"].Incarnation,
	}
	if err := config.SaveProjectTo(a.RepositoryDir, cfg); err != nil {
		t.Fatal(err)
	}
	previous, err := a.ReadConfig()
	if err != nil {
		t.Fatal(err)
	}
	delete(cfg.Environments, "scratch")
	content, err := config.MarshalProject(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.WriteConfig(string(content), previous); !apperr.Is(err, apperr.CodeEnvironmentMissing) {
		t.Fatalf("repair with a missing default: %v", err)
	}
	cfg.DefaultEnv = "default"
	content, err = config.MarshalProject(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.WriteConfig(string(content), previous); err != nil {
		t.Fatalf("repair with an existing default: %v", err)
	}
}

func TestPurgeIncarnationRefusesLiveLegacyName(t *testing.T) {
	alice := newAlice(t)
	const name = "7b26d19e-bb13-4e98-9300-9cbc96403aea"
	cfg, err := alice.loadProject()
	if err != nil {
		t.Fatal(err)
	}
	cfg.Environments[name] = config.EnvironmentConfig{Output: config.DefaultOutput(name)}
	if err := config.SaveProjectTo(alice.RepositoryDir, cfg); err != nil {
		t.Fatal(err)
	}
	if err := alice.AddSecret(bg, name, "LEGACY", "keep"); err != nil {
		t.Fatal(err)
	}
	if _, err := alice.PurgeIncarnation(bg, name); !apperr.Is(err, apperr.CodeInvalidArgument) {
		t.Fatalf("purging a live legacy history: %v", err)
	}
	if got := mustSecrets(t, alice, name)["LEGACY"]; got != "keep" {
		t.Fatalf("legacy history changed: %q", got)
	}
}

// noDelete is a backend that cannot delete, like a registry without a provider API.
type noDelete struct{ storage.Store }

func (noDelete) CanDelete() bool { return false }

func (noDelete) Delete(context.Context, storage.Kind, string, digest.Digest) error {
	return storage.ErrUnsupported
}

// Purging must not delete secrets for a deletion that will then be refused.
func TestDeleteEnvironmentPurgingChecksEverythingBeforeDeleting(t *testing.T) {
	alice := newAlice(t)
	// "default" is the current environment, which cannot be deleted.
	deleted, err := alice.DeleteEnvironment(bg, "default", true)
	if !apperr.Is(err, apperr.CodeInvalidArgument) || deleted.Purged != 0 {
		t.Fatalf("deleting the current environment: %+v %v", deleted, err)
	}
	if left := revisionsOf(t, alice, "default"); len(left) == 0 {
		t.Fatal("secrets were deleted although the environment could not be")
	}
	if _, err := alice.DeleteEnvironment(bg, "missing", true); !apperr.Is(err, apperr.CodeEnvironmentMissing) {
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
	if _, err := alice.DeleteEnvironment(bg, "dev", true); !apperr.Is(err, apperr.CodeInvalidArgument) {
		t.Fatalf("a backend that cannot delete: %v", err)
	}
	alice.Storage = real
	if envs, _ := alice.ListEnvironments(); len(envs) != 2 {
		t.Fatalf("the environment was removed anyway: %+v", envs)
	}
	if left := revisionsOf(t, alice, "dev"); len(left) == 0 {
		t.Fatal("secrets were deleted although the environment stayed")
	}

	deleted, err = alice.DeleteEnvironment(bg, "dev", true)
	if err != nil || deleted.Purged != 1 {
		t.Fatalf("deleting with purge: %+v %v", deleted, err)
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
	if _, err := alice.DeleteEnvironment(bg, "dev", false); err != nil {
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
