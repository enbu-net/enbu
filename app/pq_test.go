package app

import (
	"strings"
	"testing"

	"github.com/enbu-net/enbu/pkg/identity"
	"github.com/enbu-net/enbu/pkg/storage"
)

// pqKeys is the real identity store, which creates hybrid ML-KEM-768 +
// X25519 keyring identities by default.
func pqKeys(t *testing.T) *identity.Manager {
	t.Helper()
	return &identity.Manager{Dir: t.TempDir(), Mode: "keyring", Vault: identityVault{}}
}

// stanzas returns the age header of the latest default revision.
func stanzas(t *testing.T, a *App) string {
	t.Helper()
	s, err := a.openSession(bg)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	read, err := s.readResource(bg, s.resource("default"), nil, false)
	if err != nil || len(read.heads) != 1 {
		t.Fatalf("read: %v", err)
	}
	h := read.heads[0]
	ciphertext, err := storage.ReadPayload(bg, a.Storage, storage.KindState, h.Scope(), h.Digest, storage.MaxPayloadBytes)
	if err != nil {
		t.Fatal(err)
	}
	header, _, _ := strings.Cut(string(ciphertext), "\n---")
	return header
}

func mustRead(t *testing.T, a *App, key, want string) {
	t.Helper()
	got, err := a.ListSecrets(bg, "default")
	if err != nil || got[key] != want {
		t.Fatalf("%s = %q, %v; want %q", key, got[key], err, want)
	}
}

// A workspace stores only post-quantum stanzas, one per member, and every
// member reads every revision with the real identity store.
func TestWorkspaceIsPostQuantumEndToEnd(t *testing.T) {
	alice := &App{Storage: newMemRegistry(), Identities: pqKeys(t), CheckpointDir: t.TempDir(),
		TokenProvider: &staticTokenProvider{token: "tok", username: "alice"}, RepoDetector: &staticRepoDetector{owner: "owner", repo: "repo"}}
	prepareApp(t, alice, "default")
	if _, err := alice.InitializeRepository(bg, InitOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := alice.AddSecret(bg, "default", "KEY", "v1"); err != nil {
		t.Fatal(err)
	}
	if h := stanzas(t, alice); strings.Count(h, "-> mlkem768x25519 ") != 1 {
		t.Fatalf("founder revision is not post-quantum:\n%.200s", h)
	}
	bob := newDevice(t, alice)
	bob.Identities = pqKeys(t)
	if err := alice.ApproveMember(bg, requestJoin(t, bob).DeviceID); err != nil {
		t.Fatal(err)
	}
	if h := stanzas(t, alice); strings.Count(h, "-> mlkem768x25519 ") != 2 {
		t.Fatalf("approval did not re-encrypt for both members:\n%.200s", h)
	}
	for _, a := range []*App{alice, bob} {
		mustRead(t, a, "KEY", "v1")
	}
}
