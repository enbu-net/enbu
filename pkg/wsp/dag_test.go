package wsp

import (
	"reflect"
	"testing"

	"github.com/opencontainers/go-digest"
)

func d(s string) digest.Digest { return digest.FromString(s) }

func sorted(ds ...digest.Digest) []digest.Digest { sortDigests(ds); return ds }

func TestGraphHeadsAndMergeBase(t *testing.T) {
	g := NewGraph()
	a, b, c := d("a"), d("b"), d("c")
	g.Add(a, nil)
	g.Add(b, []digest.Digest{a})
	g.Add(c, []digest.Digest{a})
	if got := g.Heads(); !reflect.DeepEqual(got, sorted(b, c)) {
		t.Fatalf("heads = %v", got)
	}
	if got := g.MergeBases([]digest.Digest{b, c}); !reflect.DeepEqual(got, []digest.Digest{a}) {
		t.Fatalf("merge base = %v", got)
	}
	m := d("m")
	g.Add(m, sorted(b, c))
	if got := g.Heads(); !reflect.DeepEqual(got, []digest.Digest{m}) {
		t.Fatalf("heads after merge = %v", got)
	}
}

func TestGraphCrissCrossHasTwoMergeBases(t *testing.T) {
	// Each branch merged the other's tip: x and y both have b and c as parents.
	g := NewGraph()
	a, b, c := d("a"), d("b"), d("c")
	x, y := d("x"), d("y")
	g.Add(a, nil)
	g.Add(b, []digest.Digest{a})
	g.Add(c, []digest.Digest{a})
	g.Add(x, sorted(b, c))
	g.Add(y, sorted(b, c))
	if got := g.MergeBases([]digest.Digest{x, y}); !reflect.DeepEqual(got, sorted(b, c)) {
		t.Fatalf("criss-cross bases = %v", got)
	}
}

func TestGraphUnrelatedRootsAndMissingParents(t *testing.T) {
	g := NewGraph()
	a, b, ghost := d("a"), d("b"), d("ghost")
	g.Add(a, nil)
	g.Add(b, []digest.Digest{ghost})
	if got := g.MergeBases([]digest.Digest{a, b}); len(got) != 0 {
		t.Fatalf("unrelated roots share %v", got)
	}
	if got := g.Missing(); !reflect.DeepEqual(got, []digest.Digest{ghost}) {
		t.Fatalf("missing = %v", got)
	}
	if got := g.Heads(); !reflect.DeepEqual(got, sorted(a, b)) {
		t.Fatalf("heads = %v", got)
	}
}
