package app

import (
	"testing"
)

// dropFromLocalConfig makes a's enbu.toml forget env, as happens when another
// member created the environment and a never pulled that commit.
func dropFromLocalConfig(t *testing.T, a *App, env string) {
	t.Helper()
	cfg, err := a.loadProject()
	if err != nil {
		t.Fatal(err)
	}
	if err := cfg.RemoveEnvironment(env); err != nil {
		t.Fatal(err)
	}
	if err := a.saveProject(cfg); err != nil {
		t.Fatal(err)
	}
}

// Approving re-encrypts every environment in storage, not only the ones the
// admin's own enbu.toml lists.
func TestApprovalReencryptsEnvironmentsMissingFromTheAdminsConfig(t *testing.T) {
	alice := newAlice(t)
	if err := alice.CreateEnvironment("dev"); err != nil {
		t.Fatal(err)
	}
	if err := alice.AddSecret(bg, "dev", "DEV", "d"); err != nil {
		t.Fatal(err)
	}
	bob := newDevice(t, alice) // bob's enbu.toml knows dev
	dropFromLocalConfig(t, alice, "dev")
	if err := alice.ApproveMember(bg, requestJoin(t, bob).DeviceID); err != nil {
		t.Fatal(err)
	}
	got, err := bob.ListSecrets(bg, "dev")
	if err != nil || got["DEV"] != "d" {
		t.Fatalf("bob cannot read an environment the admin's config does not list: %v %v", got, err)
	}
}

// Removing re-encrypts those environments too, so the removed recipient is
// dropped from every ciphertext in storage.
func TestRemovalReencryptsEnvironmentsMissingFromTheAdminsConfig(t *testing.T) {
	alice := newAlice(t)
	if err := alice.CreateEnvironment("dev"); err != nil {
		t.Fatal(err)
	}
	if err := alice.AddSecret(bg, "dev", "DEV", "d"); err != nil {
		t.Fatal(err)
	}
	bob := newDevice(t, alice)
	id := requestJoin(t, bob).DeviceID
	if err := alice.ApproveMember(bg, id); err != nil {
		t.Fatal(err)
	}
	dropFromLocalConfig(t, alice, "dev")
	before, _, err := alice.Storage.Refs.Get(bg, secretsTag("dev"))
	if err != nil {
		t.Fatal(err)
	}
	if err := alice.RemoveMember(bg, id); err != nil {
		t.Fatal(err)
	}
	after, _, err := alice.Storage.Refs.Get(bg, secretsTag("dev"))
	if err != nil {
		t.Fatal(err)
	}
	if before == after {
		t.Fatal("dev was not re-encrypted after the removal")
	}
}
