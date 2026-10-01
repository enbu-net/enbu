package cli

import (
	"testing"

	"github.com/enbu-net/enbu/app"
)

func TestIdentityCommandsWithoutAuthentication(t *testing.T) {
	store := &staticKeyStore{}
	a := &app.App{Identities: store, RepoDetector: &deleteTestRepoDetector{}}
	created := executeJSON(t, NewWithApp("test", a), "identity", "create", "--json")
	shown := executeJSON(t, NewWithApp("test", a), "identity", "show", "--json")
	if objectField(t, created, "data")["recipient"] != objectField(t, shown, "data")["recipient"] {
		t.Fatal("identity show changed recipient")
	}
	if objectField(t, shown, "data")["backend"] != "keyring" {
		t.Fatal("backend omitted")
	}
	// Doctor needs neither token provider nor repository detector.
	doctor := executeJSON(t, NewWithApp("test", &app.App{Identities: store}), "doctor", "--json")
	if objectField(t, doctor, "data")["fallback_available"] != true {
		t.Fatal("fallback result omitted")
	}
}
