package cli

import (
	"strings"
	"testing"

	"github.com/enbu-net/enbu/app"
	"github.com/enbu-net/enbu/pkg/apperr"
)

func conflictsFixture() []app.SecretConflict {
	return []app.SecretConflict{
		{Key: "A", Candidates: []app.ConflictCandidate{{Value: "one"}, {Value: "two"}}},
		{Key: "B", Candidates: []app.ConflictCandidate{{Deleted: true}, {Value: "kept"}}},
	}
}

func TestParseChoices(t *testing.T) {
	got, err := parseChoices(conflictsFixture(), []string{"A=typed=value"}, []string{"B=1"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got["A"] != (app.SecretChoice{Value: "typed=value"}) || got["B"] != (app.SecretChoice{Delete: true}) {
		t.Fatalf("choices = %+v", got)
	}
	got, err = parseChoices(conflictsFixture(), nil, []string{"A=2"}, []string{"B"})
	if err != nil || got["A"].Value != "two" || !got["B"].Delete {
		t.Fatalf("choices = %+v %v", got, err)
	}
}

func TestParseChoicesRejectsWhatItCannotMean(t *testing.T) {
	for name, tc := range map[string]struct{ values, picks, deletes []string }{
		"not a conflict":     {values: []string{"C=x"}},
		"missing equals":     {values: []string{"A"}},
		"pick out of range":  {picks: []string{"A=3"}},
		"pick zero":          {picks: []string{"A=0"}},
		"pick not a number":  {picks: []string{"A=x"}},
		"decided twice":      {values: []string{"A=x"}, deletes: []string{"A"}},
		"delete not on list": {deletes: []string{"C"}},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := parseChoices(conflictsFixture(), tc.values, tc.picks, tc.deletes)
			if !apperr.Is(err, apperr.CodeInvalidArgument) {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

func TestResolveListsNothingWhenThereAreNoConflicts(t *testing.T) {
	a, _ := newSeededApp(t, map[string]string{"KEY": "value"})
	cmd := NewWithApp("test", a)
	var out strings.Builder
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"resolve"})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "No conflicts") {
		t.Fatalf("output = %q", out.String())
	}
}
