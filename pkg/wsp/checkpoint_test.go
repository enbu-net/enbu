package wsp

import (
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"

	digest "github.com/opencontainers/go-digest"
)

// stateView builds a view from revision names and the parents they list.
func stateView(edges map[string][]string) *StateView {
	g := NewGraph()
	for name, parents := range edges {
		var ps []digest.Digest
		for _, p := range parents {
			ps = append(ps, d(p))
		}
		g.Add(d(name), ps)
	}
	sv := &StateView{Graph: g, States: map[digest.Digest]*VerifiedState{}}
	for _, h := range g.Heads() {
		sv.Heads = append(sv.Heads, &VerifiedState{Digest: h})
	}
	return sv
}

func TestStateCheckpointRejectsAViewThatLostAnAcceptedHead(t *testing.T) {
	cps := OpenCheckpoints(t.TempDir(), testWorkspace, d("genesis"))
	if err := cps.CheckStates(testResource, stateView(map[string][]string{"a": nil}).Graph); err != nil {
		t.Fatalf("nothing accepted yet: %v", err)
	}
	// Two writers raced: a and b are both heads, both accepted.
	if err := acceptView(cps, stateView(map[string][]string{"root": nil, "a": {"root"}, "b": {"root"}})); err != nil {
		t.Fatal(err)
	}
	// Storage later shows only a: b vanished.
	if err := cps.CheckStates(testResource, stateView(map[string][]string{"root": nil, "a": {"root"}}).Graph); !errors.Is(err, ErrRollback) {
		t.Fatalf("lost head: %v", err)
	}
	// A merge of a and b contains both as ancestors, so it is progress.
	merged := stateView(map[string][]string{"root": nil, "a": {"root"}, "b": {"root"}, "m": {"a", "b"}})
	if err := cps.CheckStates(testResource, merged.Graph); err != nil {
		t.Fatalf("merge after fork: %v", err)
	}
	if err := acceptView(cps, merged); err != nil {
		t.Fatal(err)
	}
	got, err := cps.State(testResource)
	if err != nil || len(got) != 1 || got[0] != d("m") {
		t.Fatalf("accepted heads = %v %v", got, err)
	}
	// Going back to the pre-merge fork is now a rollback too: m is gone.
	if err := acceptView(cps, stateView(map[string][]string{"root": nil, "a": {"root"}, "b": {"root"}})); !errors.Is(err, ErrRollback) {
		t.Fatalf("accepting an older view: %v", err)
	}
	// Resources have separate checkpoints.
	if err := cps.CheckStates("secrets/prod", stateView(map[string][]string{"x": nil}).Graph); err != nil {
		t.Fatalf("other resource: %v", err)
	}
}

func acceptView(c *Checkpoints, sv *StateView) error {
	heads := make([]digest.Digest, len(sv.Heads))
	for i, h := range sv.Heads {
		heads[i] = h.Digest
	}
	return c.AcceptStates(testResource, sv.Graph, heads)
}

func controlView(names ...string) *ControlView {
	v := &ControlView{verified: map[digest.Digest]*Verified{}}
	for _, n := range names {
		x := &Verified{Digest: d(n)}
		v.verified[x.Digest] = x
		v.Heads = append(v.Heads, x)
	}
	sortVerified(v.Heads)
	return v
}

func TestControlCheckpointNeverMovesBack(t *testing.T) {
	cps := OpenCheckpoints(t.TempDir(), testWorkspace, d("genesis"))
	if err := cps.AcceptControl(controlView("g1")); err != nil {
		t.Fatal(err)
	}
	// A view that no longer holds g1 is a rollback.
	if err := cps.AcceptControl(controlView("other")); !errors.Is(err, ErrRollback) {
		t.Fatalf("control view without the accepted head: %v", err)
	}
	// A newer view that still holds g1 advances the checkpoint.
	newer := controlView("g1", "g2")
	newer.Heads = newer.Heads[:0]
	newer.Heads = append(newer.Heads, newer.verified[d("g2")])
	if err := cps.AcceptControl(newer); err != nil {
		t.Fatal(err)
	}
	got, err := cps.Control()
	if err != nil || len(got) != 1 || got[0] != d("g2") {
		t.Fatalf("accepted control heads = %v %v", got, err)
	}
	if err := cps.AcceptControl(controlView("g1")); !errors.Is(err, ErrRollback) {
		t.Fatalf("older control view: %v", err)
	}
}

func TestCheckpointFilesAreSeparatePerWorkspaceAndGenesis(t *testing.T) {
	dir := t.TempDir()
	a := OpenCheckpoints(dir, testWorkspace, d("genesis-a"))
	b := OpenCheckpoints(dir, testWorkspace, d("genesis-b"))
	if err := acceptView(a, stateView(map[string][]string{"x": nil})); err != nil {
		t.Fatal(err)
	}
	if got, _ := b.State(testResource); got != nil {
		t.Fatalf("another genesis shares the checkpoint: %v", got)
	}
}

func TestCorruptAndOldCheckpointFiles(t *testing.T) {
	dir := t.TempDir()
	cps := OpenCheckpoints(dir, testWorkspace, d("genesis"))
	if err := os.WriteFile(cps.path, []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := cps.Control(); err == nil {
		t.Fatal("corrupt checkpoint accepted")
	}
	if err := os.WriteFile(cps.path, []byte(`{"version":99}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := cps.Control(); err == nil {
		t.Fatal("unsupported future version accepted")
	}
	// A file of the old single-digest format carries nothing over and starts empty.
	if err := os.WriteFile(cps.path, []byte(`{"version":1,"control":{"generation":3,"digest":"x"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := cps.Control(); err != nil || got != nil {
		t.Fatalf("old format: %v %v", got, err)
	}
	if filepath.Dir(cps.path) != dir {
		t.Fatal("checkpoint escaped its directory")
	}
}

func TestConcurrentAcceptsKeepTheNewestView(t *testing.T) {
	cps := OpenCheckpoints(t.TempDir(), testWorkspace, d("genesis"))
	other := OpenCheckpoints(filepath.Dir(cps.path), testWorkspace, d("genesis"))
	views := []*StateView{
		stateView(map[string][]string{"r": nil}),
		stateView(map[string][]string{"r": nil, "a": {"r"}}),
		stateView(map[string][]string{"r": nil, "a": {"r"}, "b": {"a"}}),
	}
	var wg sync.WaitGroup
	for i, v := range views {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c := cps
			if i%2 == 1 {
				c = other
			}
			_ = acceptView(c, v) // older views may be rejected once a newer one is in
		}()
	}
	wg.Wait()
	got, err := cps.State(testResource)
	if err != nil || len(got) != 1 {
		t.Fatalf("heads = %v %v", got, err)
	}
	// Whatever won, the checkpoint never holds something a later view must lose.
	if err := cps.CheckStates(testResource, views[2].Graph); err != nil {
		t.Fatalf("newest view rejected: %v", err)
	}
}
