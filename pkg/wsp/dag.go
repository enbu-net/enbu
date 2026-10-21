package wsp

import (
	"sort"

	"github.com/opencontainers/go-digest"
)

// Graph is a set of revisions and the parents each one names. Parents that are
// not in the set are ignored when computing heads and ancestors: the caller
// decides whether a missing parent is a problem.
type Graph struct {
	parents map[digest.Digest][]digest.Digest
}

func NewGraph() *Graph { return &Graph{parents: map[digest.Digest][]digest.Digest{}} }

func (g *Graph) Add(d digest.Digest, parents []digest.Digest) {
	g.parents[d] = append([]digest.Digest(nil), parents...)
}

func (g *Graph) Has(d digest.Digest) bool { _, ok := g.parents[d]; return ok }

func (g *Graph) Len() int { return len(g.parents) }

// Parents returns the parents a revision names, whether or not they are in the graph.
func (g *Graph) Parents(d digest.Digest) []digest.Digest { return g.parents[d] }

// Missing lists parents that revisions name but the graph does not hold.
func (g *Graph) Missing() []digest.Digest {
	seen := map[digest.Digest]bool{}
	var out []digest.Digest
	for _, ps := range g.parents {
		for _, p := range ps {
			if !g.Has(p) && !seen[p] {
				seen[p] = true
				out = append(out, p)
			}
		}
	}
	sortDigests(out)
	return out
}

// Heads returns the revisions no other revision names as a parent, sorted.
func (g *Graph) Heads() []digest.Digest {
	child := map[digest.Digest]bool{}
	for _, ps := range g.parents {
		for _, p := range ps {
			child[p] = true
		}
	}
	var heads []digest.Digest
	for d := range g.parents {
		if !child[d] {
			heads = append(heads, d)
		}
	}
	sortDigests(heads)
	return heads
}

// Ancestors returns d and everything reachable through parents inside the graph.
func (g *Graph) Ancestors(d digest.Digest) map[digest.Digest]bool {
	seen := map[digest.Digest]bool{}
	stack := []digest.Digest{d}
	for len(stack) > 0 {
		cur := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if seen[cur] || !g.Has(cur) {
			continue
		}
		seen[cur] = true
		stack = append(stack, g.parents[cur]...)
	}
	return seen
}

// MergeBases returns the lowest common ancestors of heads: the common ancestors
// that are not themselves an ancestor of another common ancestor. There is more
// than one only after a criss-cross merge. It is empty when the heads share no
// history.
func (g *Graph) MergeBases(heads []digest.Digest) []digest.Digest {
	if len(heads) == 0 {
		return nil
	}
	common := g.Ancestors(heads[0])
	for _, h := range heads[1:] {
		anc := g.Ancestors(h)
		for d := range common {
			if !anc[d] {
				delete(common, d)
			}
		}
	}
	shadowed := map[digest.Digest]bool{}
	for d := range common {
		for a := range g.Ancestors(d) {
			if a != d {
				shadowed[a] = true
			}
		}
	}
	var bases []digest.Digest
	for d := range common {
		if !shadowed[d] {
			bases = append(bases, d)
		}
	}
	sortDigests(bases)
	return bases
}

func sortDigests(ds []digest.Digest) {
	sort.Slice(ds, func(i, j int) bool { return ds[i] < ds[j] })
}
