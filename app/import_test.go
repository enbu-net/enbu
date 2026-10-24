package app

import (
	"testing"

	"github.com/enbu-net/enbu/pkg/apperr"
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
	// key fills the shared GUI message; keys lists them for callers.
	if params := apperr.PayloadOf(err).Params; params["key"] != "KEY" || params["keys"] != "KEY" {
		t.Fatalf("params = %v", params)
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
