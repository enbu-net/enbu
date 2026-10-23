package app

import (
	"context"
	"fmt"
	"slices"
	"sync"
	"testing"

	"github.com/enbu-net/enbu/pkg/age"
	"github.com/enbu-net/enbu/pkg/apperr"
	"github.com/enbu-net/enbu/pkg/bundle"
	"github.com/enbu-net/enbu/pkg/config"
	"github.com/enbu-net/enbu/pkg/storage"
	"github.com/enbu-net/enbu/pkg/storage/storagetest"
	"github.com/opencontainers/go-digest"
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

// Anyone able to write to storage can create scopes without limit. The bound
// counts every unlisted scope examined, not only those with a trusted head, so
// junk scopes cannot make a membership change examine all of them.
func TestScopeDiscoveryIsBounded(t *testing.T) {
	prev := maxExaminedScopes
	maxExaminedScopes = 2
	t.Cleanup(func() { maxExaminedScopes = prev })

	alice := newAlice(t)
	outsider := newDevice(t, alice)
	requestJoin(t, outsider)
	s, err := alice.openSession(bg)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, err := age.EncryptForPublicKeys(bundle.Marshal(map[string]string{"X": "junk"}), s.head.Recipients())
	if err != nil {
		t.Fatal(err)
	}
	for i := range 5 {
		publishRevision(t, alice.Storage, outsider, s.workspace, fmt.Sprintf("secrets/junk-%d", i), s.head.Digest, ciphertext)
	}
	defaultScope := storage.StateScope(s.workspace, s.resource("default"))
	s.Close()

	var mu sync.Mutex
	touched := map[string]bool{}
	alice.Storage = storagetest.Wrap(alice.Storage, storagetest.Hooks{
		Discover: func(ctx context.Context, next storage.Store, kind storage.Kind, scope string) ([]digest.Digest, error) {
			if kind == storage.KindState && scope != defaultScope {
				mu.Lock()
				touched[scope] = true
				mu.Unlock()
			}
			return next.Discover(ctx, kind, scope)
		},
	})
	s, err = alice.openSession(bg)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	targets, unexamined, err := s.environmentResources(bg)
	if err != nil {
		t.Fatal(err)
	}
	if unexamined != 3 || len(touched) != 2 {
		t.Fatalf("examined %d scopes and left %d, want 2 and 3", len(touched), unexamined)
	}
	if len(targets) != 1 || targets[0].resource != s.resource("default") {
		t.Fatalf("targets = %+v, want only the listed environment", targets)
	}

	// A membership change still re-encrypts what enbu.toml lists, and says
	// that some scopes were left unexamined instead of hiding it.
	bob := newDevice(t, alice)
	err = alice.ApproveMember(bg, requestJoin(t, bob).DeviceID)
	if !apperr.Is(err, apperr.CodeReencryptIncomplete) {
		t.Fatalf("approval with unexamined scopes: %v", err)
	}
	if got := mustSecrets(t, bob, "default"); got["KEY"] != "v1" {
		t.Fatalf("the listed environment was not re-encrypted: %v", got)
	}
}

// A revision signed by someone the current Control does not list, built on the
// current head and dated last, must not reach history: not as an entry, not
// through a diff, and not through a restore of any entry.
func TestHistoryNeverShowsRevisionsFromNonMembers(t *testing.T) {
	for name, author := range map[string]func(t *testing.T, alice *App) *App{
		"never a member": func(t *testing.T, alice *App) *App {
			outsider := newDevice(t, alice)
			requestJoin(t, outsider)
			return outsider
		},
		"removed member": func(t *testing.T, alice *App) *App {
			bob := approved(t, alice)
			if err := alice.RemoveMember(bg, mustMember(t, alice, bob).DeviceID); err != nil {
				t.Fatal(err)
			}
			return bob
		},
	} {
		t.Run(name, func(t *testing.T) {
			alice := newAlice(t)
			if err := alice.EditSecret(bg, "default", "KEY", "v2"); err != nil {
				t.Fatal(err)
			}
			forger := author(t, alice)
			before, err := alice.ListHistory(bg, "default")
			if err != nil {
				t.Fatal(err)
			}

			s, err := alice.openSession(bg)
			if err != nil {
				t.Fatal(err)
			}
			ciphertext, err := age.EncryptForPublicKeys(bundle.Marshal(map[string]string{"KEY": "v2", "PLANTED": "x"}), s.head.Recipients())
			if err != nil {
				t.Fatal(err)
			}
			sv, err := s.loadResource(bg, s.resource("default"))
			if err != nil {
				t.Fatal(err)
			}
			// It names the current Control and the current head, as a member's would.
			publishRevisionAt(t, alice.Storage, forger, s.workspace, s.resource("default"), s.head.Digest, ciphertext, 4000000000, sv.Heads[0].Digest)
			s.Close()

			after, err := alice.ListHistory(bg, "default")
			if err != nil {
				t.Fatal(err)
			}
			if len(after) != len(before) {
				t.Fatalf("history lists the forged revision: %d -> %d entries", len(before), len(after))
			}
			for i := range after {
				if after[i].Tag != before[i].Tag {
					t.Fatalf("entry %d changed from %s to %s", i+1, before[i].Tag, after[i].Tag)
				}
			}
			if len(after) >= 2 {
				diff, err := alice.DiffHistory(bg, "default", len(after)-1, len(after))
				if err != nil {
					t.Fatal(err)
				}
				if slices.Contains(diff.Added, "PLANTED") {
					t.Fatalf("diff shows the forged key: %+v", diff)
				}
			}
			for i := range after {
				if err := alice.RestoreHistory(bg, "default", i+1); err != nil {
					t.Fatal(err)
				}
				if got := mustSecrets(t, alice, "default"); got["PLANTED"] != "" {
					t.Fatalf("restoring entry %d published the forged content", i+1)
				}
			}
		})
	}
}
