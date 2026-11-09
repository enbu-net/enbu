package simulation

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
)

func integer(t *testing.T, name string, def int) int {
	t.Helper()
	s := os.Getenv(name)
	if s == "" {
		return def
	}
	v, e := strconv.Atoi(s)
	if e != nil || v < 1 {
		t.Fatalf("%s must be positive", name)
	}
	return v
}
func exercise(t *testing.T, seed uint64, plan Plan) *Tape {
	t.Helper()
	sampleCase(t)
	return baseline(t, seed, plan)
}

// baseline runs a world without incremental sampling. Use it for a parent's
// measurement run whose child cases call exercise: sampling both levels would
// keep a child only when the parent and child names land in the same sample.
func baseline(t *testing.T, seed uint64, plan Plan) *Tape {
	t.Helper()
	tape, e := Prepare(seed, revision(t), plan)
	if e != nil {
		t.Fatal(e)
	}
	dir := os.Getenv("ENBU_SIM_ARTIFACTS")
	if dir != "" {
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(dir, fmt.Sprintf("%d-%s.journal", seed, strings.ReplaceAll(t.Name(), "/", "_")))
		file, err := os.Create(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := json.NewEncoder(file).Encode(tape.Recording); err != nil {
			t.Fatal(err)
		}
		tape.Journal = file
		defer func() {
			_ = file.Close()
			if !t.Failed() && os.Getenv("ENBU_SIM_SAVE_ALL") != "1" {
				_ = os.Remove(path)
			}
		}()
	}
	defer func() {
		if t.Failed() {
			dir := os.Getenv("ENBU_SIM_ARTIFACTS")
			if dir == "" {
				dir = filepath.Join(os.TempDir(), "enbu-simulation-failures")
			}
			if err := os.MkdirAll(dir, 0700); err != nil {
				t.Error(err)
				return
			}
			path := filepath.Join(dir, fmt.Sprintf("%d-%s.json", seed, strings.ReplaceAll(t.Name(), "/", "_")))
			if err := tape.Save(path); err != nil {
				t.Error(err)
			}
		}
	}()
	e = Execute(context.Background(), tape, t.TempDir())
	if e != nil || os.Getenv("ENBU_SIM_SAVE_ALL") == "1" {
		dir := os.Getenv("ENBU_SIM_ARTIFACTS")
		if dir == "" {
			dir = filepath.Join(os.TempDir(), "enbu-simulation-failures")
		}
		if me := os.MkdirAll(dir, 0700); me != nil {
			t.Fatal(me)
		}
		path := filepath.Join(dir, fmt.Sprintf("%d-%s.json", seed, strings.ReplaceAll(t.Name(), "/", "_")))
		if se := tape.Save(path); se != nil {
			t.Fatal(se)
		}
		t.Logf("replay: ENBU_SIM_REPLAY=%s go test -count=1 ./test/simulation -run TestReplay", path)
	}
	if e != nil {
		var violation *Violation
		if errors.As(e, &violation) && len(plan.Actions) > 0 {
			var minimized *Tape
			rev := revision(t)
			// Each candidate runs two worlds. Remove them right away: a long
			// shrink would otherwise keep hundreds of world trees until the test
			// ends, which is slow to clean up on Windows.
			world := func(tape *Tape) error {
				root, err := os.MkdirTemp("", "enbu-sim-shrink-*")
				if err != nil {
					return err
				}
				defer func() { _ = os.RemoveAll(root) }()
				return Execute(context.Background(), tape, root)
			}
			reduced := Minimize(plan.Actions, func(actions []Action) bool {
				candidatePlan := plan
				candidatePlan.Actions = actions
				candidate, ce := Prepare(seed, rev, candidatePlan)
				if ce != nil {
					return false
				}
				ce = world(candidate)
				var v *Violation
				if !errors.As(ce, &v) || v.Kind != violation.Kind {
					return false
				}
				replay := &Tape{Recording: candidate.Recording, Replay: true}
				re := world(replay)
				var rv *Violation
				if !errors.As(re, &rv) || rv.Kind != v.Kind || replay.Finish() != nil {
					return false
				}
				minimized = candidate
				return true
			})
			if minimized != nil {
				dir := os.Getenv("ENBU_SIM_ARTIFACTS")
				if dir == "" {
					dir = filepath.Join(os.TempDir(), "enbu-simulation-failures")
				}
				// Matrix tests share small seeds, so the name must include the case.
				path := filepath.Join(dir, fmt.Sprintf("%d-%s-minimized.json", seed, strings.ReplaceAll(t.Name(), "/", "_")))
				if se := minimized.Save(path); se != nil {
					t.Error(se)
				}
				t.Logf("shrunk %d to %d actions: %s", len(plan.Actions), len(reduced), path)
			}
		}
		t.Fatal(e)
	}
	replay := &Tape{Recording: tape.Recording, Replay: true}
	if e := Execute(context.Background(), replay, t.TempDir()); e != nil {
		t.Fatal(e)
	}
	return tape
}
func TestSimulation(t *testing.T) {
	seeds := integer(t, "ENBU_SIM_SEEDS", 2)
	steps := integer(t, "ENBU_SIM_STEPS", 16)
	shard, shards := simulationLane(t)
	for i := 0; i < seeds; i++ {
		seed := simulationSeed(i, shards, shard, os.Getenv("GITHUB_SHA"))
		t.Run(fmt.Sprintf("seed-%d", seed), func(t *testing.T) {
			// CI lanes own parallelism. Keeping seeds serial also lets -failfast
			// stop before another expensive run and minimization is started.
			n := 2 + int(seed%7)
			scenario := Scenarios[int(seed%uint64(len(Scenarios)))]
			if (scenario == "control-fork" || scenario == "team-incident") && n < 3 {
				n = 3
			}
			exercise(t, seed, Plan{Devices: n, Scenario: scenario, Actions: Generate(seed, steps, n)})
		})
	}
}

func simulationSeed(index, shards, shard int, revision string) uint64 {
	seed := uint64((index/2)*shards + shard)
	if index%2 == 1 {
		h := fnv.New64a()
		_, _ = h.Write([]byte(revision))
		seed = ((seed ^ h.Sum64()) & ((1 << 63) - 1)) | (1 << 63)
	}
	return seed
}
func TestScenarios(t *testing.T) {
	for i, name := range Scenarios {
		t.Run(name, func(t *testing.T) { shardCase(t); exercise(t, uint64(10000+i), Plan{Devices: 3, Scenario: name}) })
	}
}
func TestReplay(t *testing.T) {
	path := os.Getenv("ENBU_SIM_REPLAY")
	if path == "" {
		t.Skip("set ENBU_SIM_REPLAY to an exact recording")
	}
	tape, e := LoadTape(path)
	if e != nil {
		t.Fatal(e)
	}
	if e := Execute(context.Background(), tape, t.TempDir()); e != nil {
		t.Fatal(e)
	}
}
func TestReplayAcrossProcesses(t *testing.T) {
	tape, e := Prepare(7, "", Plan{Devices: 3, Scenario: "concurrent-keys", Actions: Generate(7, 8, 3)})
	if e != nil {
		t.Fatal(e)
	}
	if e := Execute(context.Background(), tape, t.TempDir()); e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(t.TempDir(), "replay.json")
	if e := tape.Save(path); e != nil {
		t.Fatal(e)
	}
	binary, e := os.Executable()
	if e != nil {
		t.Fatal(e)
	}
	for i := 0; i < 3; i++ {
		cmd := exec.Command(binary, "-test.run=^TestReplay$", "-test.count=1")
		cmd.Env = append(os.Environ(), "ENBU_SIM_REPLAY="+path)
		if output, e := cmd.CombinedOutput(); e != nil {
			t.Fatalf("replay process: %v\n%s", e, output)
		}
	}
}

var revisions sync.Map // PATH -> git revision, so cases do not spawn git each time

func revision(t *testing.T) string {
	t.Helper()
	if sha := os.Getenv("GITHUB_SHA"); sha != "" {
		return sha
	}
	// Keyed by PATH: a test that hides git must still see "unknown".
	path := os.Getenv("PATH")
	if rev, ok := revisions.Load(path); ok {
		return rev.(string)
	}
	cmd := exec.Command("git", "rev-parse", "HEAD")
	out, err := cmd.Output()
	if err != nil {
		t.Logf("revision unavailable: %v", err)
		return "unknown"
	}
	rev := strings.TrimSpace(string(out))
	revisions.Store(path, rev)
	return rev
}

func TestSimulationSmokeWithoutGitMetadata(t *testing.T) {
	t.Setenv("GITHUB_SHA", "")
	t.Setenv("PATH", t.TempDir())
	tape := exercise(t, 107, Plan{Devices: 2, Scenario: "concurrent-keys"})
	if tape.Recording.Revision != "unknown" {
		t.Fatal("source-only execution did not retain placeholder revision metadata")
	}
}

func TestSimulationSmokeJournalPreservesEveryRecordedEntry(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("ENBU_SIM_ARTIFACTS", dir)
	t.Setenv("ENBU_SIM_SAVE_ALL", "1")
	tape := exercise(t, 109, Plan{Devices: 2, Scenario: "file-output"})
	paths, err := filepath.Glob(filepath.Join(dir, "*.journal"))
	if err != nil || len(paths) != 1 {
		t.Fatalf("journal not retained: paths=%v err=%v", paths, err)
	}
	file, err := os.Open(paths[0])
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = file.Close() }()
	decoder := json.NewDecoder(file)
	var header Recording
	if err := decoder.Decode(&header); err != nil || header.Seed != 109 {
		t.Fatalf("journal header missing: %v", err)
	}
	for index, want := range tape.Recording.Entries {
		var got Entry
		if err := decoder.Decode(&got); err != nil || !reflect.DeepEqual(got, want) {
			t.Fatalf("journal lost or changed entry %d: %v", index, err)
		}
	}
	var extra Entry
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		t.Fatalf("journal has unrecorded data: %v", err)
	}
}

// exploration is opt-in so ordinary unit/scenario coverage retains bounded
// regression cases instead of executing the unsharded search repeatedly.
func exploration(t *testing.T) {
	t.Helper()
	if os.Getenv("ENBU_SIM_EXPLORE") != "1" {
		t.Skip("set ENBU_SIM_EXPLORE=1 for complete simulation matrices")
	}
}
func TestSimulationSmoke(t *testing.T) {
	for i, plan := range []Plan{
		{Devices: 3, Concurrent: &ConcurrentCase{Left: "edit", Right: "delete", SameKey: true}},
		{Devices: 3, CompactionRace: &CompactionRaceCase{Publication: "valid", Fault: "crash-after"}},
		{Devices: 4, Clock: "backward", Compound: &CompoundCase{Control: "remove-writer", Fault: "crash-after", Resolution: "different"}},
	} {
		t.Run(fmt.Sprintf("case-%d", i), func(t *testing.T) { exercise(t, uint64(200+i), plan) })
	}
}
