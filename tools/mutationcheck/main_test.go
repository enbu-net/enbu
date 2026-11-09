package main

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/BurntSushi/toml"
)

const sample = `{"files":[{"file_name":"a.go","mutations":[
 {"type":"CONDITIONALS_NEGATION","status":"KILLED","line":1,"column":2},
 {"type":"CONDITIONALS_BOUNDARY","status":"LIVED","line":3,"column":4},
 {"type":"ARITHMETIC_BASE","status":"LIVED","line":5,"column":6},
 {"type":"INVERT_LOGICAL","status":"TIMED OUT","line":7,"column":8},
 {"type":"INVERT_LOGICAL","status":"NOT COVERED","line":9,"column":1}]}]}`

func report(t *testing.T, s string) Report {
	t.Helper()
	var r Report
	if err := json.Unmarshal([]byte(s), &r); err != nil {
		t.Fatal(err)
	}
	return r
}

func TestJudgeCountsEquivalentMutantsApart(t *testing.T) {
	target := Target{Package: "pkg/x", MinEfficacy: 70, Equivalent: []Equivalent{
		{At: "a.go:5:6", Type: "ARITHMETIC_BASE", Reason: "capacity only"},
	}}
	v := Judge(target, report(t, sample))
	if v.Killed != 1 || v.TimedOut != 1 || v.Lived != 1 || v.Equivalent != 1 || v.NotCovered != 1 {
		t.Fatalf("verdict %+v", v)
	}
	if len(v.Survivors) != 1 || !strings.Contains(v.Survivors[0], "pkg/x/a.go:3:4") {
		t.Fatalf("survivors %v", v.Survivors)
	}
	if got := Problem(target, v); !strings.Contains(got, "below 70%") {
		t.Fatalf("2 of 3 judged is below 70%%: %q", got)
	}
	target.MinEfficacy = 60
	if got := Problem(target, v); got != "" {
		t.Fatalf("2 of 3 judged passes 60%%: %q", got)
	}
	// An equivalent mutant must match its type too.
	target.Equivalent[0].Type = "CONDITIONALS_BOUNDARY"
	if v := Judge(target, report(t, sample)); v.Lived != 2 {
		t.Fatalf("an equivalent entry of another type excused a mutant: %+v", v)
	}
}

func TestProblemRejectsInconclusiveRuns(t *testing.T) {
	target := Target{Package: "pkg/x", MinEfficacy: 50}
	allTimedOut := `{"files":[{"file_name":"a.go","mutations":[{"type":"X","status":"TIMED OUT","line":1,"column":1}]}]}`
	if got := Problem(target, Judge(target, report(t, allTimedOut))); !strings.Contains(got, "nothing was judged") {
		t.Fatalf("a run where every mutant timed out must fail: %q", got)
	}
	if got := Problem(target, Judge(target, report(t, `{"files":[]}`))); got == "" {
		t.Fatal("a run without mutants must fail")
	}
	mostlyTimedOut := `{"files":[{"file_name":"a.go","mutations":[
	 {"type":"X","status":"TIMED OUT","line":1,"column":1},{"type":"X","status":"TIMED OUT","line":2,"column":1},
	 {"type":"X","status":"KILLED","line":3,"column":1}]}]}`
	if got := Problem(target, Judge(target, report(t, mostlyTimedOut))); !strings.Contains(got, "not conclusive") {
		t.Fatalf("a run dominated by timeouts must fail: %q", got)
	}
}

func TestChangedSelectsPackagesWithGoChanges(t *testing.T) {
	ts := []Target{{Package: "pkg/wsp"}, {Package: "pkg/merge"}, {Package: "app"}}
	got := Changed(ts, []string{"pkg/wsp/state.go", "pkg/merge/README.md", "app/sub/x.go", "docs/a.md"})
	if len(got) != 1 || got[0].Package != "pkg/wsp" {
		t.Fatalf("selected %v", got)
	}
}

func TestTheRepositoryTargetsAreValid(t *testing.T) {
	var ts Targets
	md, err := toml.DecodeFile("targets.toml", &ts)
	if err != nil {
		t.Fatal(err)
	}
	if len(md.Undecoded()) > 0 {
		t.Fatalf("unknown keys %v", md.Undecoded())
	}
	if err := Validate(ts); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"pkg/wsp", "pkg/merge", "pkg/signing", "pkg/age", "pkg/dotenv"} {
		found := false
		for _, target := range ts.Target {
			found = found || target.Package == want
		}
		if !found {
			t.Errorf("security package %s has no mutation target", want)
		}
	}
	if err := Validate(Targets{Target: []Target{{Package: "x", MinEfficacy: 50, Equivalent: []Equivalent{{At: "a.go:1:1", Type: "X"}}}}}); err == nil {
		t.Fatal("an equivalent mutant without a reason must be rejected")
	}
}
