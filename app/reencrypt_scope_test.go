package app

import (
	"testing"

	"github.com/enbu-net/enbu/pkg/age"
	"github.com/enbu-net/enbu/pkg/bundle"
	"github.com/enbu-net/enbu/pkg/config"
	"github.com/enbu-net/enbu/pkg/storage"
)

// addEnvironmentOn creates env in d's own enbu.toml only, as a member does
// before committing the change.
func addEnvironmentOn(t *testing.T, d *App, env string) string {
	t.Helper()
	cfg, err := d.loadProject()
	if err != nil {
		t.Fatal(err)
	}
	if err := cfg.AddEnvironment(env); err != nil {
		t.Fatal(err)
	}
	if err := config.SaveProjectTo(d.RepositoryDir, cfg); err != nil {
		t.Fatal(err)
	}
	return cfg.Resource(env)
}

func readAs(t *testing.T, d *App, resource string) (map[string]string, error) {
	t.Helper()
	s, err := d.openSession(bg)
	if err != nil {
		return nil, err
	}
	defer s.Close()
	read, err := s.readResource(bg, resource, nil, true)
	if err != nil {
		return nil, err
	}
	return read.secrets, nil
}

// An environment another member created, whose enbu.toml the admin has not
// pulled, is re-encrypted on approval and on removal like any other.
func TestReencryptionCoversEnvironmentsMissingFromConfig(t *testing.T) {
	alice := newEmptyAlice(t)
	bob := approved(t, alice)
	qa := addEnvironmentOn(t, bob, "qa")
	if err := bob.AddSecret(bg, "qa", "K", "only in bob's enbu.toml"); err != nil {
		t.Fatal(err)
	}

	carol := newDevice(t, alice)
	if err := alice.ApproveMember(bg, requestJoin(t, carol).DeviceID); err != nil {
		t.Fatal(err)
	}
	if got, err := readAs(t, carol, qa); err != nil || got["K"] != "only in bob's enbu.toml" {
		t.Fatalf("the new member cannot read an environment the admin's enbu.toml lacks: %v %v", got, err)
	}

	if err := alice.RemoveMember(bg, mustMember(t, alice, carol).DeviceID); err != nil {
		t.Fatal(err)
	}
	s, err := alice.openSession(bg)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	read, err := s.readResource(bg, qa, nil, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(read.heads) != 1 || read.heads[0].Control != s.head.Digest {
		t.Fatalf("the environment was not re-encrypted for the members after the removal: %+v", read.heads)
	}
}

// Anyone able to write to storage can make a scope that holds only revisions
// from non-members. It has nothing to re-encrypt, so it must neither be
// re-encrypted nor make the membership change report a failure.
func TestReencryptionSkipsScopesWithoutATrustedRevision(t *testing.T) {
	alice := newAlice(t)
	outsider := newDevice(t, alice)
	requestJoin(t, outsider) // has a signing key, but is not a member
	s, err := alice.openSession(bg)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, err := age.EncryptForPublicKeys(bundle.Marshal(map[string]string{"X": "junk"}), s.head.Recipients())
	if err != nil {
		t.Fatal(err)
	}
	junk := "secrets/junk"
	publishRevision(t, alice.Storage, outsider, s.workspace, junk, s.head.Digest, ciphertext)
	s.Close()

	bob := newDevice(t, alice)
	if err := alice.ApproveMember(bg, requestJoin(t, bob).DeviceID); err != nil {
		t.Fatalf("a junk scope failed the approval: %v", err)
	}
	revs, err := alice.Storage.Discover(bg, storage.KindState, storage.StateScope(mustWorkspace(t, alice), junk))
	if err != nil || len(revs) != 1 {
		t.Fatalf("the junk scope was re-encrypted: %v %v", revs, err)
	}
}

// A removed member keeps a signing key the old Control lists, so they can sign
// a revision naming that Control. Reading sets it aside; history must not list
// it either, or restoring it would publish its content under a member's
// signature.
func TestHistoryOmitsRevisionsSetAsideAsHeads(t *testing.T) {
	alice := newAlice(t)
	bob := approved(t, alice)
	bobsView, err := bob.openSession(bg)
	if err != nil {
		t.Fatal(err)
	}
	defer bobsView.Close()
	oldControl := bobsView.head.Digest
	if err := alice.RemoveMember(bg, mustMember(t, alice, bob).DeviceID); err != nil {
		t.Fatal(err)
	}
	before, err := alice.ListHistory(bg, "default")
	if err != nil {
		t.Fatal(err)
	}

	s, err := alice.openSession(bg)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, err := age.EncryptForPublicKeys(bundle.Marshal(map[string]string{"KEY": "planted"}), s.head.Recipients())
	if err != nil {
		t.Fatal(err)
	}
	sv, err := s.loadResource(bg, s.resource("default"))
	if err != nil {
		t.Fatal(err)
	}
	// Dated far in the future, so it would be the newest entry.
	publishRevisionAt(t, alice.Storage, bob, s.workspace, s.resource("default"), oldControl, ciphertext, 4000000000, sv.Heads[0].Digest)
	s.Close()

	after, err := alice.ListHistory(bg, "default")
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != len(before) {
		t.Fatalf("history lists a revision from a removed member: before %d, after %d entries", len(before), len(after))
	}
	if err := alice.RestoreHistory(bg, "default", len(after)); err != nil {
		t.Fatal(err)
	}
	if got := mustSecrets(t, alice, "default"); got["KEY"] == "planted" {
		t.Fatal("restoring the newest entry published the planted content")
	}
}
