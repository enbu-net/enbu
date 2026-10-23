package app

import (
	"errors"
	"testing"

	apptest "github.com/enbu-net/enbu/app/apptest"
	"github.com/enbu-net/enbu/pkg/apperr"
	"github.com/enbu-net/enbu/pkg/config"
	"github.com/enbu-net/enbu/pkg/storage"
	"github.com/enbu-net/enbu/pkg/wsp"
)

func setGenesis(t *testing.T, a *App, genesis string) {
	t.Helper()
	cfg, err := a.loadProject()
	if err != nil {
		t.Fatal(err)
	}
	cfg.ControlGenesis = genesis
	if err := config.SaveProjectTo(a.RepositoryDir, cfg); err != nil {
		t.Fatal(err)
	}
}

func genesisOf(t *testing.T, a *App) string {
	t.Helper()
	cfg, err := a.loadProject()
	if err != nil {
		t.Fatal(err)
	}
	return cfg.ControlGenesis
}

// foundRival makes mallory, who can write to storage and to enbu.toml, found a
// second Control for alice's workspace in the same storage. It returns its genesis.
func foundRival(t *testing.T, alice *App) string {
	t.Helper()
	mallory := newDevice(t, alice)
	setGenesis(t, mallory, "")
	if err := apptest.Control(bg, mallory.Storage, mallory.RepositoryDir, mallory.Identities); err != nil {
		t.Fatal(err)
	}
	return genesisOf(t, mallory)
}

// A commit that points enbu.toml at another genesis must not re-root this
// device's trust: every operation stops until a person accepts the new genesis.
func TestChangedGenesisStopsEveryOperation(t *testing.T) {
	alice := newAlice(t)
	trusted := genesisOf(t, alice)
	rival := foundRival(t, alice)
	setGenesis(t, alice, rival)
	before := revisionsOf(t, alice, "default")

	ops := map[string]func() error{
		"list":    func() error { _, err := alice.ListSecrets(bg, "default"); return err },
		"add":     func() error { return alice.AddSecret(bg, "default", "NEW", "leaked") },
		"members": func() error { _, err := alice.ListMembers(bg); return err },
		"history": func() error { _, err := alice.ListHistory(bg, "default"); return err },
		"init":    func() error { _, err := alice.InitializeRepository(bg); return err },
	}
	for name, op := range ops {
		err := op()
		var ae *apperr.Error
		if !errors.As(err, &ae) || ae.Code() != apperr.CodeTrustRootChanged {
			t.Fatalf("%s: got %v, want trust_root_changed", name, err)
		}
		if p := ae.Params(); p["pinned"] != trusted || p["configured"] != rival {
			t.Fatalf("%s: params %v", name, p)
		}
	}
	if after := revisionsOf(t, alice, "default"); len(after) != len(before) {
		t.Fatalf("a write went through under the new genesis: %d -> %d revisions", len(before), len(after))
	}
}

// After an admin confirms out of band that the workspace was re-founded, the
// new genesis can be accepted explicitly, and it then replaces the old one.
func TestAcceptNewGenesisReplacesThePin(t *testing.T) {
	alice := newAlice(t)
	trusted := genesisOf(t, alice)
	rival := foundRival(t, alice)
	setGenesis(t, alice, rival)

	alice.AcceptNewGenesis = true
	result, err := alice.InitializeRepository(bg)
	alice.AcceptNewGenesis = false
	if err != nil {
		t.Fatal(err)
	}
	if result.ReplacedGenesis != trusted || result.ControlGenesis != rival {
		t.Fatalf("result names %q -> %q, want %q -> %q", result.ReplacedGenesis, result.ControlGenesis, trusted, rival)
	}
	if !result.Pending {
		t.Fatal("alice is not a member of the new Control, so she must wait for approval")
	}
	if _, err := alice.ListSecrets(bg, "default"); apperr.Is(err, apperr.CodeTrustRootChanged) {
		t.Fatalf("the accepted genesis is still rejected: %v", err)
	}
	// Accepting is not sticky: going back is another change of trust root.
	setGenesis(t, alice, trusted)
	if _, err := alice.ListSecrets(bg, "default"); !apperr.Is(err, apperr.CodeTrustRootChanged) {
		t.Fatalf("the old genesis was accepted again silently: %v", err)
	}
	// Accepting the same genesis again reports no replacement.
	setGenesis(t, alice, rival)
	alice.AcceptNewGenesis = true
	result, err = alice.InitializeRepository(bg)
	alice.AcceptNewGenesis = false
	if err != nil || result.ReplacedGenesis != "" {
		t.Fatalf("re-accepting the pinned genesis: %+v %v", result, err)
	}
}

// Emptied storage plus an enbu.toml without control_genesis would let init
// found a new workspace under the same ID. A device that already trusts a
// genesis refuses before publishing anything.
func TestPinnedDeviceDoesNotFoundTheWorkspaceAgain(t *testing.T) {
	alice := newAlice(t)
	trusted := genesisOf(t, alice)
	setGenesis(t, alice, "")
	alice.Storage = newMemRegistry()

	_, err := alice.InitializeRepository(bg)
	var ae *apperr.Error
	if !errors.As(err, &ae) || ae.Code() != apperr.CodeTrustRootChanged || ae.Params()["pinned"] != trusted {
		t.Fatalf("founded the workspace again: %v", err)
	}
	if revs, err := alice.Storage.Discover(bg, storage.KindControl, ""); err != nil || len(revs) != 0 {
		t.Fatalf("a genesis was published: %v %v", revs, err)
	}
	if got := genesisOf(t, alice); got != "" {
		t.Fatalf("enbu.toml records a new genesis %s", got)
	}
}

// Only a genesis that verified against storage is pinned, so a mistyped or
// unreachable genesis on the first run does not become the trust root.
func TestUnverifiedGenesisIsNotPinned(t *testing.T) {
	alice := newAlice(t)
	bob := newDevice(t, alice)
	trusted := genesisOf(t, bob)
	setGenesis(t, bob, "sha256:0000000000000000000000000000000000000000000000000000000000000000")
	if _, err := bob.InitializeRepository(bg); !apperr.Is(err, apperr.CodeIncompatibleStorage) {
		t.Fatalf("unknown genesis: %v", err)
	}
	if pinned, err := bob.trustRoot(mustWorkspace(t, bob)).Pinned(); err != nil || pinned != (wsp.Root{}) {
		t.Fatalf("an unverified genesis was pinned: %q %v", pinned, err)
	}
	setGenesis(t, bob, trusted)
	if _, err := bob.InitializeRepository(bg); err != nil {
		t.Fatalf("the real genesis was rejected after a failed first attempt: %v", err)
	}
}

// enbu.toml holds the workspace ID as well, so a commit can change both
// fields and point at a workspace the device has never pinned. The
// repository's own pin still stops it.
func TestChangedWorkspaceAndGenesisStillStops(t *testing.T) {
	alice := newAlice(t)
	trusted := genesisOf(t, alice)
	original := mustWorkspace(t, alice)

	// Mallory founds a workspace of their own and commits its enbu.toml.
	mallory := &App{Storage: alice.Storage, Identities: newMemKeyStore(), CheckpointDir: t.TempDir(), RepositoryDir: t.TempDir()}
	cfg, err := alice.loadProject()
	if err != nil {
		t.Fatal(err)
	}
	cfg.WorkspaceID = "22222222-2222-4222-8222-222222222222"
	cfg.ControlGenesis = ""
	if err := config.SaveProjectTo(mallory.RepositoryDir, cfg); err != nil {
		t.Fatal(err)
	}
	if err := apptest.Control(bg, mallory.Storage, mallory.RepositoryDir, mallory.Identities); err != nil {
		t.Fatal(err)
	}
	cfg.ControlGenesis = genesisOf(t, mallory)
	if err := config.SaveProjectTo(alice.RepositoryDir, cfg); err != nil {
		t.Fatal(err)
	}

	for name, op := range map[string]func() error{
		"init": func() error { _, err := alice.InitializeRepository(bg); return err },
		"list": func() error { _, err := alice.ListSecrets(bg, "default"); return err },
	} {
		err := op()
		var ae *apperr.Error
		if !errors.As(err, &ae) || ae.Code() != apperr.CodeTrustRootChanged {
			t.Fatalf("%s: got %v, want trust_root_changed", name, err)
		}
		if p := ae.Params(); p["pinned_workspace"] != original || p["pinned"] != trusted || p["configured_workspace"] != cfg.WorkspaceID {
			t.Fatalf("%s: params %v", name, p)
		}
	}
	if revs, err := alice.Storage.Discover(bg, storage.KindRequest, ""); err != nil || len(revs) != 0 {
		t.Fatalf("alice asked to join mallory's workspace: %v %v", revs, err)
	}
}

// Founding a workspace hands trust to nobody else, so a checkout that founds a
// new one moves its repository pin without --accept-new-genesis.
func TestFoundingAgainInTheSameCheckoutMovesThePin(t *testing.T) {
	alice := newAlice(t)
	cfg, err := alice.loadProject()
	if err != nil {
		t.Fatal(err)
	}
	cfg.WorkspaceID = "33333333-3333-4333-8333-333333333333"
	cfg.ControlGenesis = ""
	if err := config.SaveProjectTo(alice.RepositoryDir, cfg); err != nil {
		t.Fatal(err)
	}
	alice.Storage = newMemRegistry()
	result, err := alice.InitializeRepository(bg)
	if err != nil {
		t.Fatalf("founding a new workspace: %v", err)
	}
	if result.ReplacedGenesis != "" || result.Pending {
		t.Fatalf("result = %+v", result)
	}
	if _, err := alice.ListSecrets(bg, "default"); err != nil && !IsNotFoundError(err) {
		t.Fatalf("the new workspace is not usable: %v", err)
	}
}
