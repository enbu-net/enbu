package merge

import (
	"fmt"
	"reflect"
	"testing"
)

// Values include deletion and the empty string as distinct states.
type referenceValue struct {
	present bool
	text    string
}

var referenceDomain = []referenceValue{{}, {present: true}, {true, "a"}, {true, "b"}}

// This is the symmetric three-way truth table, independent of the production
// multi-head reduction and candidate collection.
func referenceThreeWay(base, left, right referenceValue) (referenceValue, bool) {
	switch {
	case left == right:
		return left, true
	case left == base:
		return right, true
	case right == base:
		return left, true
	default:
		return referenceValue{}, false
	}
}
func referenceMap(v referenceValue) map[string]string {
	out := map[string]string{"UNRELATED": "kept"}
	if v.present {
		out["K"] = v.text
	}
	return out
}
func TestExhaustiveThreeWayValueMatrix(t *testing.T) {
	for bi, base := range referenceDomain {
		for li, left := range referenceDomain {
			for ri, right := range referenceDomain {
				t.Run(fmt.Sprintf("base-%d/left-%d/right-%d", bi, li, ri), func(t *testing.T) {
					want, clean := referenceThreeWay(base, left, right)
					for _, heads := range [][]map[string]string{{referenceMap(left), referenceMap(right)}, {referenceMap(right), referenceMap(left)}, {referenceMap(left), referenceMap(right), referenceMap(left)}} {
						got, conflicts := Merge([]map[string]string{referenceMap(base)}, heads, nil)
						expected := referenceMap(want)
						if !clean {
							delete(expected, "K")
						}
						if !reflect.DeepEqual(got, expected) {
							t.Fatalf("got %v want %v", got, expected)
						}
						if clean {
							if len(conflicts) != 0 {
								t.Fatalf("false conflict: %+v", conflicts)
							}
						} else {
							if len(conflicts) != 1 || conflicts[0].Key != "K" {
								t.Fatalf("missing conflict: %+v", conflicts)
							}
							actual := map[Value]bool{}
							for _, candidate := range conflicts[0].Candidates {
								actual[candidate] = true
							}
							candidates := map[Value]bool{{Text: left.text, Deleted: !left.present}: true, {Text: right.text, Deleted: !right.present}: true}
							if !reflect.DeepEqual(actual, candidates) {
								t.Fatalf("candidates got %v want %v", actual, candidates)
							}
						}
						// A choice never changes a non-conflicted key or creates an unknown key.
						for _, choice := range []Choice{{Value: "chosen"}, {Delete: true}} {
							resolved, remaining := Merge([]map[string]string{referenceMap(base)}, heads, map[string]Choice{"K": choice, "UNRELATED": {Delete: true}, "UNKNOWN": {Value: "must-not-appear"}})
							result := referenceMap(want)
							if !clean {
								if choice.Delete {
									delete(result, "K")
								} else {
									result["K"] = choice.Value
								}
							}
							if len(remaining) != 0 || !reflect.DeepEqual(resolved, result) {
								t.Fatalf("choice got %v conflicts %v want %v", resolved, remaining, result)
							}
						}
					}
				})
			}
		}
	}
}
