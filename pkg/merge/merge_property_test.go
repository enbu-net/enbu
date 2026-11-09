package merge

import (
	"maps"
	"reflect"
	"slices"
	"testing"

	"pgregory.net/rapid"
)

// MERGE-1, checked on generated inputs. A small key and value space makes
// concurrent changes collide often.

var (
	propKeys   = []string{"A", "B", "C"}
	propValues = []string{"1", "2", "3"}
)

func genMap(t *rapid.T, label string) map[string]string {
	m := map[string]string{}
	for _, k := range propKeys {
		if rapid.Bool().Draw(t, label+" has "+k) {
			m[k] = rapid.SampledFrom(propValues).Draw(t, label+" "+k)
		}
	}
	return m
}

func genMaps(t *rapid.T, label string, minN, maxN int) []map[string]string {
	n := rapid.IntRange(minN, maxN).Draw(t, label+" count")
	out := make([]map[string]string, n)
	for i := range out {
		out[i] = genMap(t, label)
	}
	return out
}

func value(m map[string]string, k string) Value {
	if v, ok := m[k]; ok {
		return Value{Text: v}
	}
	return Value{Deleted: true}
}

func result(m map[string]string, k string, conflicts []Conflict) (Value, bool) {
	for _, c := range conflicts {
		if c.Key == k {
			return Value{}, false
		}
	}
	return value(m, k), true
}

func TestMergeProperties(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		bases := genMaps(t, "base", 0, 2)
		heads := genMaps(t, "head", 1, 4)
		out, conflicts := Merge(bases, heads, nil)

		// The order and repetition of heads change nothing: a stale listing or
		// a revision seen twice must not change the outcome.
		perm := rapid.Permutation(heads).Draw(t, "order")
		out2, conflicts2 := Merge(bases, append(perm, perm[0]), nil)
		if !reflect.DeepEqual(out, out2) || !reflect.DeepEqual(conflicts, conflicts2) {
			t.Fatalf("reordered or repeated heads changed the merge:\n%v %v\n%v %v", out, conflicts, out2, conflicts2)
		}

		effective := bases
		if len(effective) == 0 {
			effective = []map[string]string{{}}
		}
		for _, k := range propKeys {
			got, merged := result(out, k, conflicts)
			var headValues []Value
			for _, h := range heads {
				if v := value(h, k); !slices.Contains(headValues, v) {
					headValues = append(headValues, v)
				}
			}
			// Nothing is invented: a merged key takes some head's value.
			if merged && !slices.Contains(headValues, got) {
				t.Fatalf("key %s merged to %v, which no head has (%v)", k, got, headValues)
			}
			// Heads that agree never conflict.
			if len(headValues) == 1 && (!merged || got != headValues[0]) {
				t.Fatalf("key %s: every head says %v, merge gave %v (merged %v)", k, headValues[0], got, merged)
			}
			// With one base, the oracle: the heads that changed the key decide;
			// one changed value wins, several are a conflict.
			if len(effective) == 1 {
				base := value(effective[0], k)
				var changed []Value
				for _, v := range headValues {
					if v != base {
						changed = append(changed, v)
					}
				}
				switch {
				case len(changed) == 0 && (!merged || got != base):
					t.Fatalf("key %s: nobody changed %v, merge gave %v (merged %v)", k, base, got, merged)
				case len(changed) == 1 && (!merged || got != changed[0]):
					t.Fatalf("key %s: only %v changed it, merge gave %v (merged %v)", k, changed[0], got, merged)
				case len(changed) > 1 && merged:
					t.Fatalf("key %s changed differently %v but merged to %v", k, changed, got)
				}
			}
			// With several bases a key merges only if each base alone would.
			if merged && len(effective) > 1 {
				for _, b := range effective {
					one, c := Merge([]map[string]string{b}, heads, nil)
					if v, ok := result(one, k, c); !ok || v != got {
						t.Fatalf("key %s merged to %v against bases %v, but base %v gives %v (merged %v)", k, got, effective, b, v, ok)
					}
				}
			}
		}
		for _, c := range conflicts {
			if len(c.Candidates) < 2 {
				t.Fatalf("conflict %s with fewer than two candidates: %v", c.Key, c.Candidates)
			}
			// Candidates are shown in one order whatever the heads' order:
			// values before deletion, values ascending, each once.
			for i := 1; i < len(c.Candidates); i++ {
				a, b := c.Candidates[i-1], c.Candidates[i]
				if a == b || a.Deleted || (!b.Deleted && a.Text >= b.Text) {
					t.Fatalf("conflict %s candidates are not in order: %v", c.Key, c.Candidates)
				}
			}
		}

		// Choices settle exactly the conflicted keys and are ignored elsewhere.
		choices := map[string]Choice{}
		for _, k := range propKeys {
			if rapid.Bool().Draw(t, "choose "+k) {
				choices[k] = Choice{Value: rapid.SampledFrom(propValues).Draw(t, "choice "+k), Delete: rapid.Bool().Draw(t, "delete "+k)}
			}
		}
		chosen, left := Merge(bases, heads, choices)
		for _, k := range propKeys {
			conflicted := slices.ContainsFunc(conflicts, func(c Conflict) bool { return c.Key == k })
			c, picked := choices[k]
			switch {
			case conflicted && picked:
				got := value(chosen, k)
				if (c.Delete && !got.Deleted) || (!c.Delete && got != Value{Text: c.Value}) {
					t.Fatalf("choice %v for %s ignored: %v", c, k, got)
				}
			case conflicted:
				if !slices.ContainsFunc(left, func(x Conflict) bool { return x.Key == k }) {
					t.Fatalf("unsettled conflict %s disappeared", k)
				}
			default:
				if value(chosen, k) != value(out, k) {
					t.Fatalf("a choice changed the non-conflicting key %s", k)
				}
			}
		}
		if !maps.EqualFunc(out, chosen, func(a, b string) bool { return a == b }) && len(conflicts) == 0 {
			t.Fatal("choices changed a merge without conflicts")
		}
	})
}
