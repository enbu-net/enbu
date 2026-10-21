package merge

import (
	"math/rand/v2"
	"reflect"
	"testing"
)

type m = map[string]string

func TestDifferentKeysMergeAutomatically(t *testing.T) {
	base := m{"A": "1", "B": "1"}
	got, conflicts := Merge([]m{base}, []m{{"A": "2", "B": "1"}, {"A": "1", "B": "2"}}, nil)
	if len(conflicts) != 0 || !reflect.DeepEqual(got, m{"A": "2", "B": "2"}) {
		t.Fatalf("got %v %v", got, conflicts)
	}
}

func TestSameKeyDifferentValuesConflicts(t *testing.T) {
	base := m{"K": "1"}
	got, conflicts := Merge([]m{base}, []m{{"K": "2"}, {"K": "3"}}, nil)
	if len(conflicts) != 1 || conflicts[0].Key != "K" || len(conflicts[0].Candidates) != 2 {
		t.Fatalf("conflicts = %+v", conflicts)
	}
	if _, ok := got["K"]; ok {
		t.Fatal("a conflicted key must not be chosen silently")
	}
}

func TestSameKeySameValueIsNotAConflict(t *testing.T) {
	got, conflicts := Merge([]m{{"K": "1"}}, []m{{"K": "2"}, {"K": "2"}}, nil)
	if len(conflicts) != 0 || got["K"] != "2" {
		t.Fatalf("got %v %v", got, conflicts)
	}
}

func TestDeleteAgainstModifyConflicts(t *testing.T) {
	_, conflicts := Merge([]m{{"K": "1"}}, []m{{}, {"K": "2"}}, nil)
	if len(conflicts) != 1 {
		t.Fatalf("conflicts = %+v", conflicts)
	}
	got, conflicts := Merge([]m{{"K": "1"}}, []m{{}, {"K": "1"}}, nil)
	if len(conflicts) != 0 || len(got) != 0 {
		t.Fatalf("delete on one side only must win: %v %v", got, conflicts)
	}
	got, conflicts = Merge([]m{{"K": "1"}}, []m{{}, {}}, nil)
	if len(conflicts) != 0 || len(got) != 0 {
		t.Fatalf("both deleted: %v %v", got, conflicts)
	}
}

func TestNoBaseMeansEmptyBase(t *testing.T) {
	got, conflicts := Merge(nil, []m{{"A": "1"}, {"B": "2"}}, nil)
	if len(conflicts) != 0 || !reflect.DeepEqual(got, m{"A": "1", "B": "2"}) {
		t.Fatalf("got %v %v", got, conflicts)
	}
	_, conflicts = Merge(nil, []m{{"A": "1"}, {"A": "2"}}, nil)
	if len(conflicts) != 1 {
		t.Fatalf("two first writes of one key: %+v", conflicts)
	}
}

func TestThreeHeads(t *testing.T) {
	base := m{"A": "0"}
	got, conflicts := Merge([]m{base}, []m{{"A": "0", "B": "1"}, {"A": "0", "C": "2"}, {"A": "9"}}, nil)
	if len(conflicts) != 0 || !reflect.DeepEqual(got, m{"A": "9", "B": "1", "C": "2"}) {
		t.Fatalf("got %v %v", got, conflicts)
	}
	_, conflicts = Merge([]m{base}, []m{{"A": "1"}, {"A": "2"}, {"A": "2"}}, nil)
	if len(conflicts) != 1 || len(conflicts[0].Candidates) != 2 {
		t.Fatalf("conflicts = %+v", conflicts)
	}
}

func TestCrissCrossIsCautious(t *testing.T) {
	// Two bases disagree about K, so even a one-sided change is not taken silently.
	bases := []m{{"K": "1"}, {"K": "2"}}
	_, conflicts := Merge(bases, []m{{"K": "3"}, {"K": "2"}}, nil)
	if len(conflicts) != 1 {
		t.Fatalf("conflicts = %+v", conflicts)
	}
	// A key both bases agree on merges normally.
	got, conflicts := Merge([]m{{"K": "1", "J": "0"}, {"K": "2", "J": "0"}}, []m{{"K": "1", "J": "5"}, {"K": "2", "J": "0"}}, nil)
	if got["J"] != "5" {
		t.Fatalf("J = %q conflicts=%+v", got["J"], conflicts)
	}
}

func TestChoicesSettleOnlyConflicts(t *testing.T) {
	base := m{"K": "1", "X": "1"}
	heads := []m{{"K": "2", "X": "2"}, {"K": "3", "X": "1"}}
	got, conflicts := Merge([]m{base}, heads, map[string]Choice{"K": {Value: "chosen"}, "X": {Value: "ignored"}})
	if len(conflicts) != 0 || got["K"] != "chosen" || got["X"] != "2" {
		t.Fatalf("got %v %v", got, conflicts)
	}
	got, _ = Merge([]m{base}, heads, map[string]Choice{"K": {Delete: true}})
	if _, ok := got["K"]; ok {
		t.Fatal("delete choice kept the key")
	}
}

// Property: merging never loses a value that exactly one side changed, and the
// result does not depend on the order of the heads.
func TestMergeIsOrderIndependentAndKeepsOneSidedChanges(t *testing.T) {
	rng := rand.New(rand.NewPCG(1, 2))
	keys := []string{"A", "B", "C", "D"}
	vals := []string{"", "x", "y", "z"}
	randMap := func() m {
		out := m{}
		for _, k := range keys {
			if v := vals[rng.IntN(len(vals))]; v != "" {
				out[k] = v
			}
		}
		return out
	}
	for range 2000 {
		base := randMap()
		n := 2 + rng.IntN(3)
		heads := make([]m, n)
		for i := range heads {
			heads[i] = randMap()
		}
		a, ca := Merge([]m{base}, heads, nil)
		rng.Shuffle(len(heads), func(i, j int) { heads[i], heads[j] = heads[j], heads[i] })
		b, cb := Merge([]m{base}, heads, nil)
		if !reflect.DeepEqual(a, b) || !reflect.DeepEqual(ca, cb) {
			t.Fatalf("order changed the result: base=%v heads=%v", base, heads)
		}
		conflicted := map[string]bool{}
		for _, c := range ca {
			conflicted[c.Key] = true
		}
		for _, k := range keys {
			changes := map[Value]bool{}
			for _, h := range heads {
				if v := (side{h}).get(k); v != (side{base}).get(k) {
					changes[v] = true
				}
			}
			switch {
			case len(changes) == 1 && conflicted[k]:
				t.Fatalf("key %s has one distinct change yet conflicts", k)
			case len(changes) == 1:
				for v := range changes {
					if got := (side{a}).get(k); got != v {
						t.Fatalf("key %s: change %v lost, result %v", k, v, got)
					}
				}
			case len(changes) > 1 && !conflicted[k]:
				t.Fatalf("key %s changed in different ways without a conflict", k)
			}
		}
	}
}
