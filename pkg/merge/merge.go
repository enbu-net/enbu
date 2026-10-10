// Package merge combines concurrent versions of a secret map the way Git
// combines branches: against the merge base. A key changed on one side only is
// taken; a key changed identically everywhere is taken; a key changed to
// different values is a conflict that only a person can settle. Nothing is
// ever chosen silently.
package merge

import (
	"maps"
	"slices"
	"sort"
)

// Value is one side's view of a key: a value, or deleted.
type Value struct {
	Text    string
	Deleted bool
}

func (v Value) String() string {
	if v.Deleted {
		return "(deleted)"
	}
	return v.Text
}

// Conflict lists the competing outcomes for one key, without duplicates.
type Conflict struct {
	Key        string
	Candidates []Value
}

// Choice settles one conflicted key. Delete removes the key.
type Choice struct {
	Value  string
	Delete bool
}

type side struct {
	m map[string]string
}

func (s side) get(key string) Value {
	if v, ok := s.m[key]; ok {
		return Value{Text: v}
	}
	return Value{Deleted: true}
}

// Merge combines heads against bases. bases are the merge bases of the heads:
// none when they share no history (then an empty map is the base), several
// after a criss-cross merge. choices settles conflicts the caller already
// asked a person about; a choice for a key that does not conflict is ignored.
//
// With several bases a key merges automatically only if every base yields the
// same non-conflicting outcome; otherwise it is a conflict. That is more
// cautious than recursing, and never loses a value.
func Merge(bases []map[string]string, heads []map[string]string, choices map[string]Choice) (map[string]string, []Conflict) {
	if len(bases) == 0 {
		bases = []map[string]string{{}}
	}
	keys := map[string]bool{}
	for _, m := range bases {
		for k := range m {
			keys[k] = true
		}
	}
	for _, m := range heads {
		for k := range m {
			keys[k] = true
		}
	}
	out := map[string]string{}
	var conflicts []Conflict
	for _, k := range slices.Sorted(maps.Keys(keys)) {
		v, ok := resolveKey(k, bases, heads)
		if !ok {
			if c, picked := choices[k]; picked {
				if !c.Delete {
					out[k] = c.Value
				}
				continue
			}
			conflicts = append(conflicts, Conflict{Key: k, Candidates: candidates(k, heads)})
			continue
		}
		if !v.Deleted {
			out[k] = v.Text
		}
	}
	return out, conflicts
}

// resolveKey applies the single-base rule per base and requires agreement.
func resolveKey(key string, bases, heads []map[string]string) (Value, bool) {
	var agreed Value
	for i, b := range bases {
		v, ok := resolveAgainst(side{b}.get(key), key, heads)
		if !ok {
			return Value{}, false
		}
		if i > 0 && v != agreed {
			return Value{}, false
		}
		agreed = v
	}
	return agreed, true
}

// resolveAgainst: heads that equal the base changed nothing. If the rest all
// agree, that is the outcome; if none changed, the base stays.
func resolveAgainst(base Value, key string, heads []map[string]string) (Value, bool) {
	changed := Value{}
	have := false
	for _, h := range heads {
		v := side{h}.get(key)
		if v == base {
			continue
		}
		if have && v != changed {
			return Value{}, false
		}
		changed, have = v, true
	}
	if !have {
		return base, true
	}
	return changed, true
}

func candidates(key string, heads []map[string]string) []Value {
	var out []Value
	for _, h := range heads {
		v := side{h}.get(key)
		if !slices.Contains(out, v) {
			out = append(out, v)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Deleted != out[j].Deleted {
			return !out[i].Deleted
		}
		return out[i].Text < out[j].Text
	})
	return out
}
