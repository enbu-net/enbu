package app

import (
	"context"
	"testing"

	"github.com/enbu-net/enbu/pkg/apperr"
	"github.com/enbu-net/enbu/pkg/config"
	"github.com/enbu-net/enbu/pkg/storage"
	"github.com/enbu-net/enbu/pkg/storage/storagetest"
)

func TestImportSecretsAddsUpdatesAndKeepsTheRest(t *testing.T) {
	alice := newAlice(t) // KEY=v1
	res, err := alice.ImportSecrets(bg, "default", map[string]string{"KEY": "v1", "NEW": "n"}, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Added) != 1 || res.Added[0] != "NEW" || len(res.Unchanged) != 1 || len(res.Updated) != 0 {
		t.Fatalf("result = %+v", res)
	}
	// A different value for an existing key is refused unless overwriting is asked for.
	_, err = alice.ImportSecrets(bg, "default", map[string]string{"KEY": "v2"}, false)
	if !apperr.Is(err, apperr.CodeSecretExists) {
		t.Fatalf("existing key silently changed: %v", err)
	}
	got := mustSecrets(t, alice, "default")
	if got["KEY"] != "v1" || got["NEW"] != "n" {
		t.Fatalf("refused import changed storage: %v", got)
	}
	res, err = alice.ImportSecrets(bg, "default", map[string]string{"KEY": "v2"}, true)
	if err != nil || len(res.Updated) != 1 {
		t.Fatalf("overwrite: %+v %v", res, err)
	}
	if got := mustSecrets(t, alice, "default"); got["KEY"] != "v2" || got["NEW"] != "n" {
		t.Fatalf("after overwrite: %v", got)
	}
}

func TestImportSecretsIntoAnEmptyEnvironmentIsOneWrite(t *testing.T) {
	alice := newAlice(t)
	if err := alice.CreateEnvironment("dev"); err != nil {
		t.Fatal(err)
	}
	res, err := alice.ImportSecrets(bg, "dev", map[string]string{"A": "1", "B": "2"}, false)
	if err != nil || len(res.Added) != 2 {
		t.Fatalf("%+v %v", res, err)
	}
	hist, err := alice.ListHistory(bg, "dev")
	if err != nil || len(hist) != 1 {
		t.Fatalf("history = %v %v, want one entry for one import", hist, err)
	}
}

func TestImportSecretsRejectsNothing(t *testing.T) {
	alice := newAlice(t)
	if _, err := alice.ImportSecrets(bg, "default", nil, false); !apperr.Is(err, apperr.CodeInvalidArgument) {
		t.Fatalf("empty import: %v", err)
	}
}

func TestImportConflictPublicPayloadListsAllKeys(t *testing.T) {
	alice := newAlice(t)
	if err := alice.AddSecret(bg, "default", "OTHER", "old"); err != nil {
		t.Fatal(err)
	}
	_, err := alice.ImportSecrets(bg, "default", map[string]string{"KEY": "changed", "OTHER": "changed"}, false)
	p := apperr.PayloadOf(err)
	if p.Code != apperr.CodeImportConflict || p.Params["count"] != "2" || p.Params["keys"] != "KEY, OTHER" {
		t.Fatalf("payload: %#v", p)
	}
	if p.Message != "2 secrets already have different values: KEY, OTHER. Use --overwrite to replace them." {
		t.Fatal(p.Message)
	}
	got := mustSecrets(t, alice, "default")
	if got["KEY"] != "v1" || got["OTHER"] != "old" {
		t.Fatal("refused import changed secrets")
	}
}

func TestImportDotenvParsesTheFile(t *testing.T) {
	alice := newAlice(t)
	if _, err := alice.ImportDotenv(bg, EnvironmentTarget{}, []byte("UNSCOPED=value\n"), false); !apperr.Is(err, apperr.CodeInvalidArgument) {
		t.Fatalf("unscoped import: %v", err)
	}
	target := importTestTarget(t, alice)
	res, err := alice.ImportDotenv(bg, target, []byte("NEW=n\n# comment\nOTHER=\"quoted value\"\n"), false)
	if err != nil || len(res.Added) != 2 {
		t.Fatalf("%+v %v", res, err)
	}
	if got := mustSecrets(t, alice, "default"); got["OTHER"] != "quoted value" {
		t.Fatalf("imported: %v", got)
	}
	if _, err := alice.ImportDotenv(bg, target, []byte("not a dotenv line"), false); !apperr.Is(err, apperr.CodeInvalidArgument) {
		t.Fatalf("invalid dotenv: %v", err)
	}
}

func importTestTarget(t *testing.T, a *App) EnvironmentTarget {
	t.Helper()
	cfg, err := a.loadProject()
	if err != nil {
		t.Fatal(err)
	}
	return EnvironmentTarget{WorkspaceID: cfg.WorkspaceID, Environment: "default", Incarnation: cfg.Environments["default"].Incarnation}
}

func TestImportRetryKeepsTheCapturedIncarnation(t *testing.T) {
	alice := newAlice(t)
	bob := approved(t, alice)
	bobID := mustMember(t, alice, bob).DeviceID
	if err := alice.CreateEnvironment("scratch"); err != nil {
		t.Fatal(err)
	}
	cfg, err := alice.loadProject()
	if err != nil {
		t.Fatal(err)
	}
	target := EnvironmentTarget{WorkspaceID: cfg.WorkspaceID, Environment: "default",
		Incarnation: cfg.Environments["default"].Incarnation}
	scope := storage.StateScope(cfg.WorkspaceID, cfg.Resource("default"))
	writes := 0
	alice.Storage = storagetest.Wrap(alice.Storage, storagetest.Hooks{
		Publish: func(ctx context.Context, next storage.Store, object storage.Object) error {
			if object.Kind == storage.KindState && object.Scope == scope {
				writes++
				if writes == 1 {
					admin := *alice
					admin.Storage = next
					if err := admin.SetAdmin(ctx, bobID, true); err != nil {
						return err
					}
					replaced, err := alice.loadProject()
					if err != nil {
						return err
					}
					replaced.Environments["default"] = replaced.Environments["scratch"]
					delete(replaced.Environments, "scratch")
					if err := config.SaveProjectTo(alice.RepositoryDir, replaced); err != nil {
						return err
					}
				}
			}
			return next.Publish(ctx, object)
		},
	})
	if _, err := alice.ImportDotenv(bg, target, []byte("IMPORTED=value\n"), false); err != nil {
		t.Fatal(err)
	}
	if writes < 2 {
		t.Fatalf("import did not retry after the membership change: %d writes", writes)
	}
	if got := mustSecrets(t, alice, "default"); got["IMPORTED"] != "" {
		t.Fatalf("import changed the replacement environment: %v", got)
	}
	s, err := alice.openSessionWith(bg, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	read, err := s.readResource(bg, cfg.Resource("default"), nil, true)
	if err != nil || read.secrets["IMPORTED"] != "value" {
		t.Fatalf("expected the import only in the captured incarnation: %v", err)
	}
}
