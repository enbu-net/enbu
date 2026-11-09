package wsp

import (
	"errors"
	"github.com/enbu-net/enbu/pkg/clock"
	"os"
	"path/filepath"
	"sync"
	"testing"

	digest "github.com/opencontainers/go-digest"
)

// stateView builds a view from revision names and the parents they list. The
// Generation of each revision is the one its parents in the view imply.
func stateView(edges map[string][]string) *StateView {
	sv := &StateView{Graph: NewGraph(), States: map[digest.Digest]*VerifiedState{}}
	var gen func(name string) uint64
	gen = func(name string) uint64 {
		var top uint64
		for _, p := range edges[name] {
			top = max(top, gen(p))
		}
		return top + 1
	}
	for name, parents := range edges {
		var ps []digest.Digest
		for _, p := range parents {
			ps = append(ps, d(p))
		}
		sv.Graph.Add(d(name), ps)
		sv.States[d(name)] = &VerifiedState{State: State{Parents: ps, Generation: gen(name)}, Digest: d(name)}
	}
	for _, h := range sv.Graph.Heads() {
		sv.Heads = append(sv.Heads, sv.States[h])
	}
	return sv
}

func acceptView(c *Checkpoints, sv *StateView) error {
	return c.AcceptState(testResource, sv, TopGeneration(sv.Heads))
}

func TestStateCheckpointRejectsAViewBelowTheAcceptedGeneration(t *testing.T) {
	cps := OpenCheckpoints(t.TempDir(), testWorkspace, d("genesis"), clock.New())
	if err := cps.CheckState(testResource, nil); err != nil {
		t.Fatalf("nothing accepted yet: %v", err)
	}
	if err := acceptView(cps, stateView(map[string][]string{"root": nil, "a": {"root"}, "b": {"a"}})); err != nil {
		t.Fatal(err)
	}
	if got, err := cps.Generation(testResource); err != nil || got != 3 {
		t.Fatalf("accepted generation = %d %v", got, err)
	}
	// Storage hides the newest revision: the view tops out at generation 2.
	if err := cps.CheckState(testResource, stateView(map[string][]string{"root": nil, "a": {"root"}})); !errors.Is(err, ErrRollback) {
		t.Fatalf("hidden newer generation: %v", err)
	}
	if err := cps.CheckState(testResource, nil); !errors.Is(err, ErrRollback) {
		t.Fatalf("everything hidden: %v", err)
	}
	if err := acceptView(cps, stateView(map[string][]string{"root": nil})); !errors.Is(err, ErrRollback) {
		t.Fatalf("accepting an older view: %v", err)
	}
	// Deleting old revisions without any record is not a rollback: the kept
	// head still carries its generation, and history ends at the missing parent.
	compacted := stateView(map[string][]string{"root": nil, "a": {"root"}, "b": {"a"}})
	delete(compacted.States, d("root"))
	delete(compacted.States, d("a"))
	compacted.Graph = NewGraph()
	compacted.Graph.Add(d("b"), []digest.Digest{d("a")})
	if err := cps.CheckState(testResource, compacted); err != nil {
		t.Fatalf("deleted old revisions: %v", err)
	}
	// Resources have separate checkpoints.
	if err := cps.CheckState("secrets/prod", stateView(map[string][]string{"x": nil})); err != nil {
		t.Fatalf("other resource: %v", err)
	}
}

// The accepted limitation of ADR-26: storage that hides an accepted head while
// showing a sibling branch of equal or higher Generation is not detected. The
// sibling needs a member's signature, and the hidden change only misses the
// next merge.
func TestStateCheckpointDoesNotDetectAHiddenHeadBehindASiblingOfEqualGeneration(t *testing.T) {
	cps := OpenCheckpoints(t.TempDir(), testWorkspace, d("genesis"), clock.New())
	if err := acceptView(cps, stateView(map[string][]string{"root": nil, "accepted": {"root"}})); err != nil {
		t.Fatal(err)
	}
	for name, sibling := range map[string]map[string][]string{
		"equal":  {"root": nil, "sibling": {"root"}},
		"higher": {"root": nil, "sibling": {"root"}, "later": {"sibling"}},
	} {
		if err := cps.CheckState(testResource, stateView(sibling)); err != nil {
			t.Fatalf("%s sibling branch hiding the accepted head was detected: %v", name, err)
		}
	}
}

func TestStateCheckpointNeverLowersTheAcceptedGeneration(t *testing.T) {
	cps := OpenCheckpoints(t.TempDir(), testWorkspace, d("genesis"), clock.New())
	view := stateView(map[string][]string{"root": nil, "a": {"root"}, "b": {"a"}})
	if err := acceptView(cps, view); err != nil {
		t.Fatal(err)
	}
	// A read that used an older trusted head of the same view keeps the higher value.
	if err := cps.AcceptState(testResource, view, 1); err != nil {
		t.Fatal(err)
	}
	if got, _ := cps.Generation(testResource); got != 3 {
		t.Fatalf("accepted generation lowered to %d", got)
	}
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
	cps := OpenCheckpoints(t.TempDir(), testWorkspace, d("genesis"), clock.New())
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
	a := OpenCheckpoints(dir, testWorkspace, d("genesis-a"), clock.New())
	b := OpenCheckpoints(dir, testWorkspace, d("genesis-b"), clock.New())
	if err := acceptView(a, stateView(map[string][]string{"x": nil})); err != nil {
		t.Fatal(err)
	}
	if got, _ := b.Generation(testResource); got != 0 {
		t.Fatalf("another genesis shares the checkpoint: %v", got)
	}
}

func TestCorruptCheckpointFile(t *testing.T) {
	dir := t.TempDir()
	cps := OpenCheckpoints(dir, testWorkspace, d("genesis"), clock.New())
	if err := os.WriteFile(cps.path, []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := cps.Control(); err == nil {
		t.Fatal("corrupt checkpoint accepted")
	}
	if filepath.Dir(cps.path) != dir {
		t.Fatal("checkpoint escaped its directory")
	}
}

// A version 3 file kept accepted heads per resource; its Control heads carry
// over and its resources start empty instead of failing every operation.
func TestVersion3CheckpointKeepsControlAndDropsStates(t *testing.T) {
	cps := OpenCheckpoints(t.TempDir(), testWorkspace, d("genesis"), clock.New())
	old := `{"version":3,"control":["` + string(d("c")) + `"],"states":{"` + testResource + `":{"heads":["` + string(d("x")) + `"],"control":"` + string(d("c")) + `"}}}`
	if err := os.WriteFile(cps.path, []byte(old), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := cps.Control(); err != nil || len(got) != 1 || got[0] != d("c") {
		t.Fatalf("control = %v %v", got, err)
	}
	if got, err := cps.Generation(testResource); err != nil || got != 0 {
		t.Fatalf("generation = %d %v", got, err)
	}
	if err := acceptView(cps, stateView(map[string][]string{"root": nil, "a": {"root"}})); err != nil {
		t.Fatal(err)
	}
	if got, err := cps.Generation(testResource); err != nil || got != 2 {
		t.Fatalf("generation after accept = %d %v", got, err)
	}
	if err := os.WriteFile(cps.path, []byte(`{"version":5}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := cps.Control(); err == nil {
		t.Fatal("a newer checkpoint format accepted")
	}
}

func TestConcurrentAcceptsKeepTheNewestView(t *testing.T) {
	cps := OpenCheckpoints(t.TempDir(), testWorkspace, d("genesis"), clock.New())
	other := OpenCheckpoints(filepath.Dir(cps.path), testWorkspace, d("genesis"), clock.New())
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
	got, err := cps.Generation(testResource)
	if err != nil || got == 0 {
		t.Fatalf("generation = %v %v", got, err)
	}
	// Whatever won, the checkpoint never holds something a later view must lose.
	if err := cps.CheckState(testResource, views[2]); err != nil {
		t.Fatalf("newest view rejected: %v", err)
	}
}
