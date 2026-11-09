// formalcheck runs the implementation-refinement models in spec/conformance
// with TLC and checks more than
// "no error": every seeded bug (mutant) must be caught by the property that
// names it, every reachability witness must be violated so the model is known
// to reach the situation its properties are about, and every action must fire
// at least once (no dead action). A model that passes vacuously fails here.
package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/BurntSushi/toml"
)

// tlcHeap is the -Xmx of every TLC process; several run at once.
var tlcHeap = "2g"

// Manifest is spec/conformance/checks.toml.
type Manifest struct {
	Model []Model `toml:"model"`
}

// Model is one TLC configuration with the checks that run against it.
type Model struct {
	Name   string `toml:"name"`
	Module string `toml:"module"`
	Config string `toml:"config"`
	// Tier is "pr" (every pull request) or "nightly" (larger bounds).
	Tier string `toml:"tier"`
	// Uncovered lists actions this configuration disables on purpose.
	Uncovered []string  `toml:"uncovered"`
	Mutant    []Mutant  `toml:"mutant"`
	Witness   []Witness `toml:"witness"`
	// MinStates guards against a configuration that stops exploring early.
	MinStates int64 `toml:"min_states"`
}

// Mutant is a seeded bug selected through the model's Mutant constant.
type Mutant struct {
	Name string `toml:"name"`
	// Violates lists the properties allowed to catch it.
	Violates []string `toml:"violates"`
}

// Witness is an invariant TLC must violate.
type Witness struct {
	Invariant string `toml:"invariant"`
}

// Job is one TLC run and what its output must show.
type Job struct {
	Label  string
	Model  Model
	Config string // contents of the .cfg file to run
	// Expect is "pass" or "violation".
	Expect   string
	Violates []string
	Coverage bool
}

// Result is the outcome of a Job.
type Result struct {
	Job      Job
	Err      error
	Duration time.Duration
	States   int64
}

var (
	reMutant    = regexp.MustCompile(`(?m)^(\s*Mutant\s*=\s*)"[^"]*"`)
	reWitnessOn = regexp.MustCompile(`(?m)^(\s*Witnessing\s*=\s*)FALSE\b`)
	reViolated  = regexp.MustCompile(`Error: Invariant (\w+) is violated`)
	reTemporal  = regexp.MustCompile(`Error: Temporal properties were violated`)
	reDistinct  = regexp.MustCompile(`([\d,]+) distinct states found`)
	reCoverage  = regexp.MustCompile(`(?m)^<(\w+) line \d+, col \d+ to line \d+, col \d+ of module \w+>: (\d+):(\d+)$`)
	reCompleted = regexp.MustCompile(`Model checking completed\. No error has been found\.`)
)

func main() {
	dir := flag.String("dir", "spec/conformance", "directory of the refinement models and checks.toml")
	tier := flag.String("tier", "pr", "tier to run: pr, nightly or all")
	run := flag.String("run", "", "only models whose name matches this regular expression")
	tlc := flag.String("tlc", "tlc", "TLC executable")
	jobs := flag.Int("jobs", max(1, runtime.NumCPU()/4), "TLC processes at once")
	workers := flag.Int("workers", 4, "TLC workers per process")
	timeout := flag.Duration("timeout", 30*time.Minute, "limit for one TLC run")
	heap := flag.String("heap", "2g", "Java heap of one TLC process (its fingerprints and queue spill to disk)")
	invariants := flag.String("invariants", "", "check this invariants table (spec/INVARIANTS.md) against the models and Go tests instead of running TLC")
	flag.Parse()
	if *invariants != "" {
		if err := CheckInvariants(*invariants, *dir, "."); err != nil {
			fmt.Fprintln(os.Stderr, "formalcheck:", err)
			os.Exit(1)
		}
		fmt.Println("every invariant is checked")
		return
	}
	tlcHeap = *heap
	if err := Run(*dir, *tier, *run, *tlc, *jobs, *workers, *timeout); err != nil {
		fmt.Fprintln(os.Stderr, "formalcheck:", err)
		os.Exit(1)
	}
}

// Run executes every check of the selected tier and fails if any expectation
// is not met.
func Run(dir, tier, run, tlc string, jobs, workers int, timeout time.Duration) error {
	m, err := Load(filepath.Join(dir, "checks.toml"))
	if err != nil {
		return err
	}
	var filter *regexp.Regexp
	if run != "" {
		if filter, err = regexp.Compile(run); err != nil {
			return err
		}
	}
	var all []Job
	for _, model := range m.Model {
		if tier != "all" && model.Tier != tier {
			continue
		}
		if filter != nil && !filter.MatchString(model.Name) {
			continue
		}
		cfg, err := os.ReadFile(filepath.Join(dir, model.Config))
		if err != nil {
			return err
		}
		js, err := Plan(model, string(cfg))
		if err != nil {
			return err
		}
		all = append(all, js...)
	}
	if len(all) == 0 {
		return fmt.Errorf("no model selected for tier %q", tier)
	}
	results := make([]Result, len(all))
	sem := make(chan struct{}, jobs)
	var wg sync.WaitGroup
	for i, j := range all {
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			results[i] = Execute(dir, tlc, workers, timeout, j)
		}()
	}
	wg.Wait()
	failed := 0
	for _, r := range results {
		status := "ok"
		if r.Err != nil {
			status, failed = "FAIL", failed+1
		}
		fmt.Printf("%-4s %-70s %8s %10d states\n", status, r.Job.Label, r.Duration.Round(100*time.Millisecond), r.States)
		if r.Err != nil {
			fmt.Printf("     %v\n", r.Err)
		}
	}
	if failed > 0 {
		return fmt.Errorf("%d of %d checks failed", failed, len(results))
	}
	fmt.Printf("all %d checks passed\n", len(results))
	return nil
}

// Load reads and validates a manifest.
func Load(path string) (*Manifest, error) {
	var m Manifest
	md, err := toml.DecodeFile(path, &m)
	if err != nil {
		return nil, err
	}
	if undecoded := md.Undecoded(); len(undecoded) > 0 {
		return nil, fmt.Errorf("%s: unknown keys %v", path, undecoded)
	}
	names := map[string]bool{}
	for _, model := range m.Model {
		switch {
		case model.Name == "" || model.Module == "" || model.Config == "":
			return nil, fmt.Errorf("%s: a model needs name, module and config", path)
		case model.Tier != "pr" && model.Tier != "nightly":
			return nil, fmt.Errorf("%s: model %q has tier %q, want pr or nightly", path, model.Name, model.Tier)
		case names[model.Name]:
			return nil, fmt.Errorf("%s: duplicate model %q", path, model.Name)
		}
		names[model.Name] = true
		for _, mu := range model.Mutant {
			if mu.Name == "" || mu.Name == "none" || len(mu.Violates) == 0 {
				return nil, fmt.Errorf("%s: model %q has a mutant without a name or the properties that catch it", path, model.Name)
			}
		}
	}
	return &m, nil
}

// Plan turns a model into its TLC runs: the model itself with coverage, one
// run per mutant, and one per witness.
func Plan(model Model, cfg string) ([]Job, error) {
	if len(model.Mutant) > 0 && !reMutant.MatchString(cfg) {
		return nil, fmt.Errorf("%s: config has no Mutant constant to seed bugs through", model.Config)
	}
	jobs := []Job{{Label: model.Name, Model: model, Config: cfg, Expect: "pass", Coverage: true}}
	for _, mu := range model.Mutant {
		jobs = append(jobs, Job{
			Label:    fmt.Sprintf("%s / mutant %s", model.Name, mu.Name),
			Model:    model,
			Config:   reMutant.ReplaceAllString(cfg, fmt.Sprintf(`${1}"%s"`, mu.Name)),
			Expect:   "violation",
			Violates: mu.Violates,
		})
	}
	for _, w := range model.Witness {
		// A model may record what it reaches only when asked, so that the
		// bookkeeping does not multiply the states of every other run.
		stripped := reWitnessOn.ReplaceAllString(withoutProperties(cfg), "${1}TRUE")
		jobs = append(jobs, Job{
			Label:    fmt.Sprintf("%s / witness %s", model.Name, w.Invariant),
			Model:    model,
			Config:   stripped + "\nINVARIANT " + w.Invariant + "\n",
			Expect:   "violation",
			Violates: []string{w.Invariant},
		})
	}
	return jobs, nil
}

// Execute runs TLC for one job in a scratch directory and checks its output.
func Execute(dir, tlc string, workers int, timeout time.Duration, j Job) Result {
	start := time.Now()
	r := Result{Job: j}
	r.Err = func() error {
		scratch, err := os.MkdirTemp("", "formalcheck-")
		if err != nil {
			return err
		}
		defer func() { _ = os.RemoveAll(scratch) }()
		entries, err := os.ReadDir(dir)
		if err != nil {
			return err
		}
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".tla") {
				continue
			}
			b, err := os.ReadFile(filepath.Join(dir, e.Name()))
			if err != nil {
				return err
			}
			if err := os.WriteFile(filepath.Join(scratch, e.Name()), b, 0o600); err != nil {
				return err
			}
		}
		if err := os.WriteFile(filepath.Join(scratch, "run.cfg"), []byte(j.Config), 0o600); err != nil {
			return err
		}
		args := []string{"-Xmx" + tlcHeap, "-workers", fmt.Sprint(workers), "-noGenerateSpecTE", "-metadir", filepath.Join(scratch, "states"), "-config", "run.cfg"}
		if j.Coverage {
			args = append(args, "-coverage", "1440")
		}
		args = append(args, j.Model.Module)
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		if strings.ContainsAny(tlc, `/\`) {
			tlc, err = filepath.Abs(tlc)
			if err != nil {
				return err
			}
		}
		cmd := exec.CommandContext(ctx, tlc, args...)
		cmd.Dir = scratch
		cmd.Env = aquaEnv(dir)
		var out bytes.Buffer
		cmd.Stdout, cmd.Stderr = &out, &out
		runErr := cmd.Run()
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return fmt.Errorf("timed out after %s", timeout)
		}
		r.States = distinctStates(out.String())
		return Judge(j, out.String(), runErr)
	}()
	r.Duration = time.Since(start)
	return r
}

// aquaEnv lets an aqua proxy for tlc find the repository's aqua.yaml although
// TLC runs in a scratch directory outside it.
func aquaEnv(specDir string) []string {
	env := os.Environ()
	if os.Getenv("AQUA_CONFIG") != "" {
		return env
	}
	if abs, err := filepath.Abs(filepath.Join(specDir, "..", "..", "aqua.yaml")); err == nil {
		if _, err := os.Stat(abs); err == nil {
			env = append(env, "AQUA_CONFIG="+abs)
		}
	}
	return env
}

func distinctStates(out string) int64 {
	m := reDistinct.FindAllStringSubmatch(out, -1)
	if len(m) == 0 {
		return 0
	}
	var n int64
	_, _ = fmt.Sscan(strings.ReplaceAll(m[len(m)-1][1], ",", ""), &n)
	return n
}

// Judge compares TLC's output with what the job expects.
func Judge(j Job, out string, runErr error) error {
	violated := ""
	if m := reViolated.FindStringSubmatch(out); m != nil {
		violated = m[1]
	} else if reTemporal.MatchString(out) {
		violated = "temporal"
	}
	switch j.Expect {
	case "pass":
		if violated != "" {
			return fmt.Errorf("property %s is violated:\n%s", violated, errorLines(out, 60))
		}
		if !reCompleted.MatchString(out) || runErr != nil {
			return fmt.Errorf("TLC did not complete (%v):\n%s", runErr, errorLines(out, 30))
		}
		if n := distinctStates(out); n < j.Model.MinStates {
			return fmt.Errorf("explored %d distinct states, fewer than min_states %d", n, j.Model.MinStates)
		}
		if j.Coverage {
			if !reCoverage.MatchString(out) {
				return errors.New("TLC output has no parseable action coverage")
			}
			if dead := DeadActions(out, j.Model.Uncovered); len(dead) > 0 {
				return fmt.Errorf("actions never taken: %s", strings.Join(dead, ", "))
			}
		}
		return nil
	case "violation":
		if violated == "" {
			if reCompleted.MatchString(out) {
				return fmt.Errorf("expected a violation of %s, but TLC found no error", strings.Join(j.Violates, " or "))
			}
			return fmt.Errorf("TLC failed without a property violation (%v):\n%s", runErr, errorLines(out, 30))
		}
		if !slices.Contains(j.Violates, violated) {
			return fmt.Errorf("expected a violation of %s, got %s", strings.Join(j.Violates, " or "), violated)
		}
		return nil
	}
	return fmt.Errorf("unknown expectation %q", j.Expect)
}

// DeadActions lists actions TLC's coverage report shows as never producing a
// state, apart from those allowed to stay unused.
func DeadActions(out string, allowed []string) []string {
	var dead []string
	for _, m := range reCoverage.FindAllStringSubmatch(out, -1) {
		name, distinct := m[1], m[2]
		if name == "Init" || distinct != "0" || slices.Contains(allowed, name) {
			continue
		}
		dead = append(dead, name)
	}
	slices.Sort(dead)
	return slices.Compact(dead)
}

// errorLines keeps TLC's own error report and the trace that follows it, or
// the last lines when there is none.
func errorLines(s string, n int) string {
	if i := strings.Index(s, "Error:"); i >= 0 {
		s = s[i:]
		lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
		if len(lines) > 4*n {
			lines = lines[:4*n]
		}
		return strings.Join(lines, "\n")
	}
	return tail(s, n)
}

func tail(s string, n int) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}
