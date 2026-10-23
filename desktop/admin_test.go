package desktop

import (
	"context"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"

	"github.com/enbu-net/enbu/app"
	"github.com/enbu-net/enbu/app/apptest"
	"github.com/enbu-net/enbu/pkg/apperr"
	"github.com/enbu-net/enbu/pkg/config"
	"github.com/enbu-net/enbu/pkg/identity"
	"github.com/enbu-net/enbu/pkg/storage"
)

func TestSetAdminPromotesAndDemotes(t *testing.T) {
	f := newMembersFixture(t)
	if err := f.alice.ApproveMember(f.bobDevice); err != nil {
		t.Fatal(err)
	}
	adminOf := func(device string) bool {
		t.Helper()
		members, err := f.alice.ListMembers()
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range members {
			if m.DeviceID == device {
				return m.Admin
			}
		}
		t.Fatalf("%s is not a member: %+v", device, members)
		return false
	}
	if err := f.alice.SetAdmin(f.bobDevice, true); err != nil {
		t.Fatal(err)
	}
	if !adminOf(f.bobDevice) {
		t.Fatal("bob was not promoted")
	}
	if err := f.alice.SetAdmin(f.bobDevice, false); err != nil {
		t.Fatal(err)
	}
	if adminOf(f.bobDevice) {
		t.Fatal("bob was not demoted")
	}
	// A device that never joined cannot be made an admin.
	if err := f.alice.SetAdmin(strings.Repeat("b", 64), true); err == nil {
		t.Fatal("promoted a stranger")
	}
}

func TestImportSecretsFromDotenv(t *testing.T) {
	f := newMembersFixture(t)
	if err := f.alice.AddSecret("", "KEEP", "same"); err != nil {
		t.Fatal(err)
	}
	if err := f.alice.AddSecret("", "OLD", "before"); err != nil {
		t.Fatal(err)
	}
	dotenv := "KEEP=same\nNEW=added\nOLD=after\n"
	if _, err := f.alice.ImportSecrets("", dotenv, false); !apperr.Is(err, apperr.CodeSecretExists) {
		t.Fatalf("import over another value without overwrite: %v", err)
	}
	res, err := f.alice.ImportSecrets("", dotenv, true)
	if err != nil {
		t.Fatal(err)
	}
	if res.Environment != "default" || strings.Join(res.Added, ",") != "NEW" || strings.Join(res.Updated, ",") != "OLD" || strings.Join(res.Unchanged, ",") != "KEEP" {
		t.Fatalf("result: %+v", res)
	}
	got, err := f.alice.ListSecrets("")
	if err != nil {
		t.Fatal(err)
	}
	values := map[string]string{}
	for _, s := range got.Secrets {
		values[s.Key] = s.Value
	}
	if values["NEW"] != "added" || values["OLD"] != "after" || values["KEEP"] != "same" {
		t.Fatalf("secrets: %+v", values)
	}
}

func TestImportSecretsRefusesAnInvalidOrEmptyFile(t *testing.T) {
	f := newMembersFixture(t)
	for name, content := range map[string]string{
		"not dotenv": "this is not a dotenv line\n",
		"empty":      "",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := f.alice.ImportSecrets("", content, false); !apperr.Is(err, apperr.CodeInvalidArgument) {
				t.Fatalf("import %q: %v", content, err)
			}
		})
	}
}

func TestDeleteEnvironmentPurgingDeletesItsRevisions(t *testing.T) {
	f := newMembersFixture(t)
	if err := f.alice.CreateEnvironment("staging"); err != nil {
		t.Fatal(err)
	}
	if err := f.alice.AddSecret("staging", "KEY", "value"); err != nil {
		t.Fatal(err)
	}
	if err := f.alice.SwitchEnvironment("default"); err != nil {
		t.Fatal(err)
	}
	purged, err := f.alice.DeleteEnvironmentPurging("staging")
	if err != nil || purged == 0 {
		t.Fatalf("purged %d: %v", purged, err)
	}
	envs, err := f.alice.ListEnvironments()
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range envs {
		if e.Name == "staging" {
			t.Fatalf("staging is still listed: %+v", envs)
		}
	}
}

func TestPurgeIncarnationDeletesAnEnvironmentDeletedEarlier(t *testing.T) {
	f := newMembersFixture(t)
	if err := f.alice.CreateEnvironment("old"); err != nil {
		t.Fatal(err)
	}
	if err := f.alice.AddSecret("old", "KEY", "value"); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.LoadProjectFrom(f.alice.repoPath)
	if err != nil {
		t.Fatal(err)
	}
	incarnation := cfg.Environments["old"].Incarnation
	if incarnation == "" {
		t.Fatal("old has no incarnation")
	}
	envs, err := f.alice.ListEnvironments()
	if err != nil {
		t.Fatal(err)
	}
	listed := ""
	for _, e := range envs {
		if e.Name == "old" {
			listed = e.Incarnation
		}
	}
	if listed != incarnation {
		t.Fatalf("listed incarnation %q, want %q", listed, incarnation)
	}
	// The environment still uses it, so it must be deleted with purging instead.
	if _, err := f.alice.PurgeIncarnation(incarnation); !apperr.Is(err, apperr.CodeInvalidArgument) {
		t.Fatalf("purging a live incarnation: %v", err)
	}
	if err := f.alice.SwitchEnvironment("default"); err != nil {
		t.Fatal(err)
	}
	if err := f.alice.DeleteEnvironment("old"); err != nil {
		t.Fatal(err)
	}
	purged, err := f.alice.PurgeIncarnation(incarnation)
	if err != nil || purged == 0 {
		t.Fatalf("purged %d: %v", purged, err)
	}
	if _, err := f.alice.PurgeIncarnation("not-a-uuid"); !apperr.Is(err, apperr.CodeInvalidArgument) {
		t.Fatalf("purging a malformed incarnation: %v", err)
	}
}

func TestOnlyAdminsCanPurge(t *testing.T) {
	f := newMembersFixture(t)
	if err := f.alice.ApproveMember(f.bobDevice); err != nil {
		t.Fatal(err)
	}
	if err := f.alice.CreateEnvironment("staging"); err != nil {
		t.Fatal(err)
	}
	if err := f.alice.AddSecret("staging", "KEY", "value"); err != nil {
		t.Fatal(err)
	}
	// bob shares alice's enbu.toml through the repository.
	cfg, err := config.LoadProjectFrom(f.alice.repoPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := config.SaveProjectTo(f.bob.repoPath, cfg); err != nil {
		t.Fatal(err)
	}
	if err := f.bob.SwitchEnvironment("default"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.bob.DeleteEnvironmentPurging("staging"); !apperr.Is(err, apperr.CodeAccessDenied) {
		t.Fatalf("a member who is not an admin purging: %v", err)
	}
	if got, err := f.alice.ListSecrets("staging"); err != nil || len(got.Secrets) != 1 {
		t.Fatalf("staging after a refused purge: %+v %v", got, err)
	}
}

// memVault keeps the identity store's secrets in memory instead of the OS keyring.
type memVault map[string][]byte

func (v memVault) Store(_, key string, value []byte) error {
	v[key] = append([]byte(nil), value...)
	return nil
}

func (v memVault) Load(_, key string) ([]byte, error) {
	b, ok := v[key]
	if !ok {
		return nil, fs.ErrNotExist
	}
	return append([]byte(nil), b...), nil
}

func (v memVault) Delete(_, key string) error { delete(v, key); return nil }

func TestUpgradeIdentityFromTheDesktop(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	t.Setenv("GITHUB_TOKEN", "")
	storageDir := t.TempDir()
	cfg := config.NewProjectWithEnvironment("default")
	cfg.Storage = config.StorageConfig{URL: "local:///" + strings.TrimPrefix(filepath.ToSlash(storageDir), "/")}
	dir := t.TempDir()
	if err := config.SaveProjectTo(dir, cfg); err != nil {
		t.Fatal(err)
	}
	a := app.New()
	// A device set up before hybrid keys were the default.
	a.Identities = &identity.Manager{Dir: t.TempDir(), Mode: "keyring", Vault: memVault{}, Classical: true}
	a.CheckpointDir = t.TempDir()
	s := NewService(a)
	s.repoPath = dir
	if err := apptest.Control(context.Background(), storage.NewLocal(storageDir), dir, a.Identities); err != nil {
		t.Fatal(err)
	}
	if err := s.AddSecret("", "KEY", "value"); err != nil {
		t.Fatal(err)
	}
	members, err := s.ListMembers()
	if err != nil || len(members) != 1 || members[0].PostQuantum {
		t.Fatalf("before: %+v %v", members, err)
	}
	// The only admin's own update is applied at once.
	res, err := s.UpgradeIdentity()
	if err != nil {
		t.Fatal(err)
	}
	if res.Pending || res.Fingerprint != members[0].Fingerprint || !strings.Contains(strings.ToLower(res.Algorithm), "mlkem") {
		t.Fatalf("result: %+v", res)
	}
	if members, err = s.ListMembers(); err != nil || !members[0].PostQuantum {
		t.Fatalf("after: %+v %v", members, err)
	}
	if got, err := s.ListSecrets(""); err != nil || len(got.Secrets) != 1 || got.Secrets[0].Value != "value" {
		t.Fatalf("secrets after upgrading: %+v %v", got, err)
	}
	if _, err := s.UpgradeIdentity(); !apperr.Is(err, apperr.CodeInvalidArgument) {
		t.Fatalf("upgrading twice: %v", err)
	}
}

func TestJoinRequestsNameKeyUpdates(t *testing.T) {
	f := newMembersFixture(t)
	requests, err := f.alice.ListJoinRequests()
	if err != nil || len(requests) != 1 || requests[0].KeyUpdate {
		t.Fatalf("a new device's request: %+v %v", requests, err)
	}
}
