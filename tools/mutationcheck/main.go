// mutationcheck runs gremlins on the security packages listed in
// targets.toml and judges its JSON report itself: gremlins' own thresholds
// exit 0 even when they fail. Every target must keep its efficacy (killed
// over killed and lived), every surviving mutant must be listed as an
// equivalent one with a reason, and a run in which nothing could be judged
// (every mutant timed out, say) fails instead of passing.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"

	"github.com/BurntSushi/toml"
)

// Targets is targets.toml.
type Targets struct {
	Target []Target `toml:"target"`
}

// Target is one package and the efficacy it must keep.
type Target struct {
	Package     string       `toml:"package"`
	MinEfficacy float64      `toml:"min_efficacy"`
	Tags        string       `toml:"tags"`
	Equivalent  []Equivalent `toml:"equivalent"`
}

// Equivalent is a mutant no test can kill because it does not change
// behavior; it must say why.
type Equivalent struct {
	At     string `toml:"at"` // file.go:line:column
	Type   string `toml:"type"`
	Reason string `toml:"reason"`
}

// Report is the part of gremlins' JSON output this tool reads.
type Report struct {
	Files []struct {
		FileName  string `json:"file_name"`
		Mutations []struct {
			Type   string `json:"type"`
			Status string `json:"status"`
			Line   int    `json:"line"`
			Column int    `json:"column"`
		} `json:"mutations"`
	} `json:"files"`
}

// Verdict is the judgement of one report.
type Verdict struct {
	Killed, Lived, Equivalent, TimedOut, NotCovered int
	Survivors                                       []string // lived and not listed as equivalent
	Efficacy                                        float64
}

func main() {
	config := flag.String("targets", "tools/mutationcheck/targets.toml", "targets file")
	gremlins := flag.String("gremlins", ".tmp/bin/gremlins", "gremlins executable")
	changed := flag.String("changed-since", "", "only targets whose package changed since this Git revision")
	workers := flag.Int("workers", max(1, runtime.NumCPU()/2), "gremlins workers")
	flag.Parse()
	if err := run(*config, *gremlins, *changed, *workers); err != nil {
		fmt.Fprintln(os.Stderr, "mutationcheck:", err)
		os.Exit(1)
	}
}

func run(config, gremlins, changedSince string, workers int) error {
	var ts Targets
	md, err := toml.DecodeFile(config, &ts)
	if err != nil {
		return err
	}
	if undecoded := md.Undecoded(); len(undecoded) > 0 {
		return fmt.Errorf("%s: unknown keys %v", config, undecoded)
	}
	if err := Validate(ts); err != nil {
		return err
	}
	selected := ts.Target
	// A new branch's first push has no previous commit (all zeros): check all.
	if strings.Trim(changedSince, "0") == "" {
		changedSince = ""
	}
	if changedSince != "" {
		out, err := exec.Command("git", "diff", "--name-only", changedSince, "--").Output()
		if err != nil {
			return fmt.Errorf("git diff: %w", err)
		}
		selected = Changed(ts.Target, strings.Fields(string(out)))
		if len(selected) == 0 {
			fmt.Println("no target package changed")
			return nil
		}
	}
	failed := 0
	for _, t := range selected {
		report, err := unleash(gremlins, t, workers)
		if err != nil {
			return fmt.Errorf("%s: %w", t.Package, err)
		}
		v := Judge(t, report)
		status := "ok"
		problem := Problem(t, v)
		if problem != "" {
			status, failed = "FAIL", failed+1
		}
		fmt.Printf("%-4s %-16s efficacy %6.2f%% (min %.0f%%): killed %d, lived %d (%d equivalent), timed out %d, not covered %d\n",
			status, t.Package, v.Efficacy, t.MinEfficacy, v.Killed, v.Lived, v.Equivalent, v.TimedOut, v.NotCovered)
		if problem != "" {
			fmt.Printf("     %s\n", problem)
		}
		for _, s := range v.Survivors {
			fmt.Printf("     survived: %s\n", s)
		}
	}
	if failed > 0 {
		return fmt.Errorf("%d of %d targets failed", failed, len(selected))
	}
	return nil
}

// Validate requires every target to have a package, a threshold and reasons
// for its equivalent mutants.
func Validate(ts Targets) error {
	if len(ts.Target) == 0 {
		return fmt.Errorf("no targets")
	}
	for _, t := range ts.Target {
		if t.Package == "" || t.MinEfficacy <= 0 || t.MinEfficacy > 100 {
			return fmt.Errorf("target %q needs a package and min_efficacy in (0, 100]", t.Package)
		}
		for _, e := range t.Equivalent {
			if e.At == "" || e.Type == "" || strings.TrimSpace(e.Reason) == "" {
				return fmt.Errorf("%s: equivalent mutant %q %q needs a reason", t.Package, e.At, e.Type)
			}
		}
	}
	return nil
}

// Changed keeps the targets with a changed Go file in their package.
func Changed(ts []Target, files []string) []Target {
	var out []Target
	for _, t := range ts {
		for _, f := range files {
			if strings.HasSuffix(f, ".go") && filepath.Dir(f) == filepath.Clean(t.Package) {
				out = append(out, t)
				break
			}
		}
	}
	return out
}

func unleash(gremlins string, t Target, workers int) (Report, error) {
	out, err := os.CreateTemp("", "gremlins-*.json")
	if err != nil {
		return Report{}, err
	}
	path := out.Name()
	_ = out.Close()
	defer func() { _ = os.Remove(path) }()
	args := []string{"unleash", "--invert-logical", "--invert-loopctrl", "--workers", fmt.Sprint(workers),
		"--timeout-coefficient", "10", "-o", path}
	if t.Tags != "" {
		args = append(args, "--tags", t.Tags)
	}
	args = append(args, "./"+filepath.Clean(t.Package))
	cmd := exec.Command(gremlins, args...)
	cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
	if err := cmd.Run(); err != nil {
		return Report{}, err
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return Report{}, err
	}
	var r Report
	if err := json.Unmarshal(b, &r); err != nil {
		return Report{}, fmt.Errorf("gremlins report: %w", err)
	}
	return r, nil
}

// Judge counts a report against a target's equivalent mutants. A timed-out
// mutant counts as killed: the tests noticed it, by never finishing.
func Judge(t Target, r Report) Verdict {
	var v Verdict
	for _, f := range r.Files {
		for _, m := range f.Mutations {
			at := fmt.Sprintf("%s:%d:%d", f.FileName, m.Line, m.Column)
			switch m.Status {
			case "KILLED":
				v.Killed++
			case "TIMED OUT":
				v.TimedOut++
			case "NOT COVERED":
				v.NotCovered++
			case "LIVED":
				if slices.ContainsFunc(t.Equivalent, func(e Equivalent) bool { return e.At == at && e.Type == m.Type }) {
					v.Equivalent++
					continue
				}
				v.Lived++
				v.Survivors = append(v.Survivors, m.Type+" at "+t.Package+"/"+at)
			}
		}
	}
	if judged := v.Killed + v.TimedOut + v.Lived; judged > 0 {
		v.Efficacy = 100 * float64(v.Killed+v.TimedOut) / float64(judged)
	}
	slices.Sort(v.Survivors)
	return v
}

// Problem says why a verdict fails its target, or "" when it passes.
func Problem(t Target, v Verdict) string {
	switch {
	case v.Killed+v.Lived == 0:
		return "nothing was judged: no mutant was killed or survived (all timed out or uncovered)"
	case v.TimedOut > v.Killed:
		return fmt.Sprintf("%d mutants timed out and only %d were killed; the run is not conclusive", v.TimedOut, v.Killed)
	case v.Efficacy < t.MinEfficacy:
		return fmt.Sprintf("efficacy %.2f%% is below %.0f%%", v.Efficacy, t.MinEfficacy)
	}
	return ""
}
