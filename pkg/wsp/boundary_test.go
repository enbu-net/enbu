package wsp

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/enbu-net/enbu/pkg/clock"
	"github.com/enbu-net/enbu/pkg/signing"
	"github.com/enbu-net/enbu/pkg/storage"
	"github.com/enbu-net/enbu/pkg/storage/storagetest"
	"github.com/opencontainers/go-digest"
)

// Boundaries and branches that mutation testing (task mutation/check) showed
// no test pinned down.

func setLimit(t *testing.T, v *int, n int) {
	t.Helper()
	old := *v
	*v = n
	t.Cleanup(func() { *v = old })
}

// lowDigest returns a listed digest that sorts before every real one and that
// storage cannot produce.
var lowDigest = digest.Digest("sha256:" + fmt.Sprintf("%064d", 0))

func listing(store storage.Store, kind storage.Kind, extra digest.Digest) storage.Store {
	return storagetest.Wrap(store, storagetest.Hooks{
		Discover: func(ctx context.Context, next storage.Store, k storage.Kind, scope string) ([]digest.Digest, error) {
			revs, err := next.Discover(ctx, k, scope)
			if k == kind {
				revs = append([]digest.Digest{extra}, revs...)
			}
			return revs, err
		},
	})
}

func TestControlCountLimitAtTheBoundary(t *testing.T) {
	store, alice, genesis := workspace(t)
	addMember(t, store, genesis, alice, newActor(t, false))
	addMember(t, store, genesis, alice, newActor(t, false)) // three Controls listed
	setLimit(t, &maxControls, 3)
	if _, err := LoadControl(context.Background(), store, testWorkspace, genesis, nil); err != nil {
		t.Fatalf("exactly maxControls Controls were refused: %v", err)
	}
	if v, err := FindGenesis(context.Background(), store, testWorkspace, alice.p.ID); err != nil || v == nil {
		t.Fatalf("FindGenesis with exactly maxControls Controls: %v %v", v, err)
	}
	maxControls = 2
	if _, err := LoadControl(context.Background(), store, testWorkspace, genesis, nil); !errors.Is(err, ErrInvalid) {
		t.Fatalf("more than maxControls Controls: %v", err)
	}
	if _, err := FindGenesis(context.Background(), store, testWorkspace, alice.p.ID); !errors.Is(err, ErrInvalid) {
		t.Fatalf("FindGenesis with more than maxControls Controls: %v", err)
	}
}

func TestGenesisByteLimitAtTheBoundary(t *testing.T) {
	store, alice, genesis := workspace(t)
	blob, err := store.FetchHead(context.Background(), storage.KindControl, "", genesis)
	if err != nil {
		t.Fatal(err)
	}
	setLimit(t, &maxControlBytes, len(blob))
	if _, err := LoadControl(context.Background(), store, testWorkspace, genesis, nil); err != nil {
		t.Fatalf("a genesis of exactly maxControlBytes was refused: %v", err)
	}
	if v, err := FindGenesis(context.Background(), store, testWorkspace, alice.p.ID); err != nil || v == nil {
		t.Fatalf("FindGenesis skipped a genesis of exactly maxControlBytes: %v %v", v, err)
	}
	maxControlBytes = len(blob) - 1
	if _, err := LoadControl(context.Background(), store, testWorkspace, genesis, nil); !errors.Is(err, ErrInvalid) {
		t.Fatalf("a genesis above maxControlBytes: %v", err)
	}
}

// A listed Control storage cannot produce is skipped; the ones after it in
// the listing are still read.
func TestAMissingListedControlDoesNotStopTheLoad(t *testing.T) {
	store, alice, genesis := workspace(t)
	child := addMember(t, store, genesis, alice, newActor(t, false))
	view, err := LoadControl(context.Background(), listing(store, storage.KindControl, lowDigest), testWorkspace, genesis, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := view.Get(child.Digest); !ok {
		t.Fatal("the Control listed after a missing one was not read")
	}
}

func TestForkHeadsAreSortedByDigest(t *testing.T) {
	store, alice, genesis := workspace(t)
	before := load(t, store, genesis)
	for range 3 {
		_, _ = UpdateControl(context.Background(), store, before, alice.signer, func(c *Control) error {
			c.Principals = append(c.Principals, newActor(t, false).p)
			return nil
		})
	}
	view := load(t, store, genesis)
	if len(view.Heads) != 3 {
		t.Fatalf("want three competing heads, got %d", len(view.Heads))
	}
	if !slices.IsSortedFunc(view.Heads, func(a, b *Verified) int { return compareDigests(a.Digest, b.Digest) }) {
		t.Fatal("fork heads are not sorted by digest")
	}
}

func compareDigests(a, b digest.Digest) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

// ResolveFork itself starts from what every head agrees on: a principal one
// branch added, one whose recipient a branch changed, and an admin right one
// branch granted are all left out.
func TestResolveForkStartsFromTheIntersection(t *testing.T) {
	store, alice, genesis := workspace(t)
	bob, carol, dave := newActor(t, false), newActor(t, false), newActor(t, false)
	addMember(t, store, genesis, alice, bob)
	base := addMember(t, store, genesis, alice, dave)
	before := load(t, store, genesis)
	if _, err := UpdateControl(context.Background(), store, before, alice.signer, func(c *Control) error {
		for i := range c.Principals {
			switch c.Principals[i].ID {
			case bob.p.ID:
				c.Principals[i].Admin = true
			case dave.p.ID:
				c.Principals[i].Recipient = newActor(t, false).p.Recipient
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	_, _ = UpdateControl(context.Background(), store, before, alice.signer, func(c *Control) error {
		c.Principals = append(c.Principals, carol.p)
		return nil
	})
	view := load(t, store, genesis)
	if !view.Forked() {
		t.Fatal("the updates did not fork")
	}
	v, err := ResolveFork(context.Background(), store, view, alice.signer, func(*Control) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, p := range v.Principals {
		got = append(got, fmt.Sprintf("%s admin=%v", p.ID[:8], p.Admin))
	}
	want := []string{fmt.Sprintf("%s admin=true", alice.p.ID[:8]), fmt.Sprintf("%s admin=false", bob.p.ID[:8])}
	slices.Sort(got)
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Fatalf("resolution of a fork from %s keeps %v, want %v", base.Digest, got, want)
	}
}

// Over a diamond in which the device stays a member, continuity holds: the
// walk must not stop at the first Control it reaches twice.
func TestMembershipContinuityOverADiamond(t *testing.T) {
	id := signing.DeviceID("device")
	view := &ControlView{verified: map[digest.Digest]*Verified{}}
	add := func(name string, parents ...string) {
		c := &Verified{Digest: d(name)}
		c.Principals = []Principal{{ID: id}}
		for _, p := range parents {
			c.Parents = append(c.Parents, d(p))
		}
		view.verified[c.Digest] = c
	}
	add("genesis")
	add("join", "genesis")
	add("left", "join")
	add("right", "join")
	add("merge", "left", "right")
	if !view.MembershipUnbroken(d("merge"), d("genesis"), id) {
		t.Fatal("membership over a diamond with no removal was reported broken")
	}
}

func TestCheckpointUpdatesWaitForTheLock(t *testing.T) {
	dir := t.TempDir()
	cps := OpenCheckpoints(dir, testWorkspace, d("genesis"), clock.New())
	release, err := lockFile(cps.path, clock.New())
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		done <- cps.AcceptState(testResource, nil, []*VerifiedState{{State: State{Generation: 2}}})
	}()
	time.Sleep(50 * time.Millisecond)
	release()
	if err := <-done; err != nil {
		t.Fatalf("an update that waited for the lock failed: %v", err)
	}
	if g, _ := cps.Generation(testResource); g != 2 {
		t.Fatalf("accepted generation %d after waiting, want 2", g)
	}
}

func TestEnvelopeNeedsBothBodyAndSignature(t *testing.T) {
	for name, s := range map[string]Signed{
		"no body":      {Signature: []byte("s")},
		"no signature": {Body: []byte("b")},
	} {
		blob, err := encMode.Marshal(s)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := DecodeSigned(blob); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestControlValidateBoundaries(t *testing.T) {
	alice, bob := newActor(t, true), newActor(t, false)
	ok := func(c Control) Control {
		c.Workspace, c.Author = testWorkspace, alice.p.ID
		if c.Principals == nil {
			c.Principals = []Principal{alice.p}
		}
		if len(c.Parents) > 0 {
			c.Height = 1
		}
		return c
	}
	parents := func(n int) []digest.Digest {
		out := make([]digest.Digest, n)
		for i := range out {
			out[i] = digest.FromString(fmt.Sprint(i))
		}
		sortDigests(out)
		return out
	}
	if err := ok(Control{Parents: parents(MaxPrincipals)}).Validate(); err != nil {
		t.Fatalf("exactly MaxPrincipals parents: %v", err)
	}
	if err := ok(Control{Parents: parents(MaxPrincipals + 1)}).Validate(); err == nil {
		t.Fatal("more than MaxPrincipals parents were accepted")
	}
	dup := parents(2)
	dup[1] = dup[0]
	if err := ok(Control{Parents: dup}).Validate(); err == nil {
		t.Fatal("a repeated parent was accepted")
	}
	twice := []Principal{alice.p, bob.p, bob.p}
	if err := ok(Control{Principals: twice}).canonical().Validate(); err == nil {
		t.Fatal("a repeated principal was accepted")
	}
}

// A genesis is accepted only from an author that is its own admin.
func TestGenesisFromANonAdminPrincipalIsRefused(t *testing.T) {
	alice, bob := newActor(t, true), newActor(t, false)
	blob, err := SignControl(Control{Workspace: testWorkspace, Principals: []Principal{alice.p, bob.p}, Author: bob.p.ID}, bob.signer)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyGenesis(testWorkspace, blob, digest.FromBytes(blob)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("a genesis signed by a member that is not an admin: %v", err)
	}
}

func TestAncestorsStayInsideTheGraph(t *testing.T) {
	for _, order := range [][]string{{"p", "missing"}, {"missing", "p"}} {
		g := NewGraph()
		g.Add(d("q"), nil)
		g.Add(d("p"), []digest.Digest{d("q")})
		g.Add(d("x"), []digest.Digest{d(order[0]), d(order[1])})
		got := g.Ancestors(d("x"))
		want := map[digest.Digest]bool{d("x"): true, d("p"): true, d("q"): true}
		if len(got) != len(want) || !got[d("p")] || !got[d("q")] || got[d("missing")] {
			t.Fatalf("parents %v: ancestors %v, want x, p and q only", order, got)
		}
	}
}

func TestAMissingListedJoinRequestDoesNotHideTheOthers(t *testing.T) {
	store := storagetest.NewMemory()
	requester := newActor(t, false)
	blob, err := NewJoinRequest(testWorkspace, requester.p.Recipient, time.Unix(1700000000, 0), requester.signer)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := PublishJoinRequest(context.Background(), store, blob); err != nil {
		t.Fatal(err)
	}
	reqs, err := ListJoinRequests(context.Background(), listing(store, storage.KindRequest, lowDigest), testWorkspace)
	if err != nil || len(reqs) != 1 {
		t.Fatalf("requests after a missing listed one: %v %v", reqs, err)
	}
}

func TestStateValidateBoundaries(t *testing.T) {
	fx := newStateFixture(t)
	base := fx.state(fx.bob, digest.FromString("p"))
	for name, mutate := range map[string]func(*State){
		"no workspace": func(s *State) { s.Workspace = "" },
		"no resource":  func(s *State) { s.Resource = "" },
		"too many parents": func(s *State) {
			s.Parents = nil
			for i := range MaxParents + 1 {
				s.Parents = append(s.Parents, digest.FromString(fmt.Sprint(i)))
			}
			sortDigests(s.Parents)
		},
	} {
		s := base
		mutate(&s)
		if err := s.validate(); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	s := base
	s.Parents = nil
	for i := range MaxParents {
		s.Parents = append(s.Parents, digest.FromString(fmt.Sprint(i)))
	}
	sortDigests(s.Parents)
	if err := s.validate(); err != nil {
		t.Fatalf("exactly MaxParents parents: %v", err)
	}
}

// A revision that fails to verify is counted and skipped; the revisions
// after it in the same batch are still read.
func TestJunkInABatchIsSkippedAndCounted(t *testing.T) {
	fx := newStateFixture(t)
	valid := fx.publish(t, fx.state(fx.bob), fx.bob, "valid")
	scope := storage.StateScope(testWorkspace, testResource)
	var order []digest.Digest
	const junk = 3
	for i := range junk {
		head := []byte(fmt.Sprintf("junk %d", i))
		rev := digest.FromBytes(head)
		if err := fx.store.Publish(context.Background(), storage.Object{Kind: storage.KindState, Scope: scope, Rev: rev, Head: head, Payload: []byte("x")}); err != nil {
			t.Fatal(err)
		}
		order = append(order, rev)
	}
	order = append(order, valid)
	store := storagetest.Wrap(fx.store, storagetest.Hooks{
		Discover: func(context.Context, storage.Store, storage.Kind, string) ([]digest.Digest, error) {
			return slices.Clone(order), nil
		},
	})
	sv, err := LoadStates(context.Background(), store, fx.view, testWorkspace, testResource)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := sv.States[valid]; !ok {
		t.Fatal("a valid revision listed after junk was not read")
	}
	if sv.Skipped != junk {
		t.Fatalf("skipped %d, want the %d junk objects", sv.Skipped, junk)
	}
}

// Every revision with a wrong Generation is dropped, however the map orders
// them.
func TestEveryWrongGenerationIsDropped(t *testing.T) {
	for range 50 {
		sv := stateView(map[string][]string{"root": nil, "a": {"root"}, "b": {"root"}, "c": {"root"}, "d": {"root"}})
		for _, n := range []string{"a", "b", "c", "d"} {
			sv.States[d(n)].Generation = 7
		}
		sv.dropWrongGenerations()
		if len(sv.States) != 1 {
			t.Fatalf("revisions with wrong generations left: %d", len(sv.States)-1)
		}
	}
}

func TestTrustFileRefusesAnEmptyRepositoryWorkspace(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "trust.json"), []byte(`{"workspaces":{},"repositories":{"/r/enbu.toml":""}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenTrust(dir, clock.New()).Repository("/r/enbu.toml"); err == nil {
		t.Fatal("a repository pinned to an empty workspace was accepted")
	}
}

// The repository pin: PinFirst refuses a different workspace for a known
// enbu.toml, PinFounded moves it, an unknown path never conflicts, and a new
// path for a pinned workspace is recorded.
func TestRepositoryPinModes(t *testing.T) {
	tr := OpenTrust(t.TempDir(), clock.New())
	a, b := root("ws-a", "genesis-a"), root("ws-b", "genesis-b")
	if _, err := tr.Pin(a, "/r/enbu.toml", PinFirst); err != nil {
		t.Fatal(err)
	}
	var changed *TrustRootChangedError
	if err := tr.Check(b, "/r/enbu.toml", PinFirst); !errors.As(err, &changed) {
		t.Fatalf("another workspace in a pinned checkout: %v", err)
	}
	if err := tr.Check(b, "/r/enbu.toml", PinFounded); err != nil {
		t.Fatalf("founding a new workspace in the checkout: %v", err)
	}
	if err := tr.Check(b, "", PinFirst); err != nil {
		t.Fatalf("an unknown enbu.toml path conflicts: %v", err)
	}
	previous, err := tr.Pin(b, "/r/enbu.toml", PinFounded)
	if err != nil {
		t.Fatal(err)
	}
	if previous != a {
		t.Fatalf("moving the repository pin reported %v, want the previous root %v", previous, a)
	}
	if _, err := tr.Pin(a, "/other/enbu.toml", PinFirst); err != nil {
		t.Fatal(err)
	}
	if got, err := tr.Repository("/other/enbu.toml"); err != nil || got != a {
		t.Fatalf("a new checkout of a pinned workspace recorded %v (%v), want %v", got, err, a)
	}
}

func TestControlPrincipalLimitAtTheBoundary(t *testing.T) {
	alice := newActor(t, true)
	principals := []Principal{alice.p}
	for len(principals) < MaxPrincipals {
		principals = append(principals, newActor(t, false).p)
	}
	c := Control{Workspace: testWorkspace, Principals: principals, Author: alice.p.ID}.canonical()
	if err := c.Validate(); err != nil {
		t.Fatalf("exactly MaxPrincipals principals: %v", err)
	}
	c.Principals = append(c.Principals, newActor(t, false).p)
	if err := c.canonical().Validate(); err == nil {
		t.Fatal("more than MaxPrincipals principals were accepted")
	}
}

func TestSortVerifiedSortsEveryOrder(t *testing.T) {
	names := []string{"a", "b", "c", "d"}
	var perms func(int)
	vs := make([]*Verified, len(names))
	for i, n := range names {
		vs[i] = &Verified{Digest: d(n)}
	}
	perms = func(k int) {
		if k == len(vs) {
			in := slices.Clone(vs)
			sortVerified(in)
			if !slices.IsSortedFunc(in, func(a, b *Verified) int { return compareDigests(a.Digest, b.Digest) }) {
				t.Fatalf("not sorted: %v", in)
			}
			return
		}
		for i := k; i < len(vs); i++ {
			vs[k], vs[i] = vs[i], vs[k]
			perms(k + 1)
			vs[k], vs[i] = vs[i], vs[k]
		}
	}
	perms(0)
}

// A wrong Generation takes every descendant with it, however the map orders
// the revisions between passes.
func TestAWrongGenerationDropsItsWholeLineage(t *testing.T) {
	for range 100 {
		sv := stateView(map[string][]string{"root": nil, "a": {"root"}, "b": {"a"}, "c": {"b"}, "e": {"c"}, "f": {"e"}})
		sv.States[d("a")].Generation = 9
		sv.dropWrongGenerations()
		if len(sv.States) != 1 || sv.Skipped != 5 {
			t.Fatalf("left %d revisions and skipped %d, want only the root and 5 skipped", len(sv.States), sv.Skipped)
		}
	}
}

// A listed revision storage cannot produce counts once as skipped, and the
// revisions after it are read.
func TestAMissingListedStateIsSkippedOnce(t *testing.T) {
	fx := newStateFixture(t)
	valid := fx.publish(t, fx.state(fx.bob), fx.bob, "valid")
	sv, err := LoadStates(context.Background(), listing(fx.store, storage.KindState, lowDigest), fx.view, testWorkspace, testResource)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := sv.States[valid]; !ok || sv.Skipped != 1 {
		t.Fatalf("valid read %v, skipped %d; want the valid revision and 1 skipped", ok, sv.Skipped)
	}
}

// The join is the same whichever head comes first, and with three heads a
// principal missing from any one of them is left out.
func TestResolveForkIsTheIntersectionInAnyHeadOrder(t *testing.T) {
	store, alice, genesis := workspace(t)
	bob, carol := newActor(t, false), newActor(t, false)
	addMember(t, store, genesis, alice, bob)
	addMember(t, store, genesis, alice, carol)
	before := load(t, store, genesis)
	branch := func(mutate func(*Control)) {
		_, _ = UpdateControl(context.Background(), store, before, alice.signer, func(c *Control) error {
			mutate(c)
			return nil
		})
	}
	// Bob is an admin on one branch only; carol is missing from the third.
	branch(func(c *Control) {
		for i := range c.Principals {
			if c.Principals[i].ID == bob.p.ID {
				c.Principals[i].Admin = true
			}
		}
	})
	branch(func(c *Control) { c.Principals = append(c.Principals, newActor(t, false).p) })
	branch(func(c *Control) {
		c.Principals = slices.DeleteFunc(c.Principals, func(p Principal) bool { return p.ID == carol.p.ID })
	})
	view := load(t, store, genesis)
	if len(view.Heads) != 3 {
		t.Fatalf("want three heads, got %d", len(view.Heads))
	}
	want := map[signing.DeviceID]bool{alice.p.ID: true, bob.p.ID: false}
	var orders [][]*Verified
	for _, perm := range [][]int{{0, 1, 2}, {1, 2, 0}, {2, 0, 1}, {2, 1, 0}} {
		orders = append(orders, []*Verified{view.Heads[perm[0]], view.Heads[perm[1]], view.Heads[perm[2]]})
	}
	for _, heads := range orders {
		v, err := ResolveFork(context.Background(), store, &ControlView{Workspace: view.Workspace, Genesis: view.Genesis, Heads: heads, verified: view.verified},
			alice.signer, func(*Control) error { return nil })
		if err != nil {
			t.Fatalf("heads in order %v: %v", heads, err)
		}
		got := map[signing.DeviceID]bool{}
		for _, p := range v.Principals {
			got[p.ID] = p.Admin
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("heads in order %v: resolution keeps %v, want alice as admin and bob as member", heads, got)
		}
	}
}
