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
			reduced := Minimize(plan.Actions, func(actions []Action) bool {
				candidatePlan := plan
				candidatePlan.Actions = actions
				candidate, ce := Prepare(seed, revision(t), candidatePlan)
				if ce != nil {
					return false
				}
				ce = Execute(context.Background(), candidate, t.TempDir())
				var v *Violation
				if !errors.As(ce, &v) || v.Kind != violation.Kind {
					return false
				}
				replay := &Tape{Recording: candidate.Recording, Replay: true}
				re := Execute(context.Background(), replay, t.TempDir())
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
				path := filepath.Join(dir, fmt.Sprintf("%d-minimized.json", seed))
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
	shards := integer(t, "ENBU_SIM_SHARDS", 1)
	shard := 0
	if raw := os.Getenv("ENBU_SIM_SHARD"); raw != "" {
		var e error
		shard, e = strconv.Atoi(raw)
		if e != nil || shard < 0 || shard >= shards {
			t.Fatal("invalid shard")
		}
	}
	for i := 0; i < seeds; i++ {
		seed := simulationSeed(i, shards, shard, os.Getenv("GITHUB_SHA"))
		t.Run(fmt.Sprintf("seed-%d", seed), func(t *testing.T) {
			t.Parallel()
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

func revision(t *testing.T) string {
	t.Helper()
	if sha := os.Getenv("GITHUB_SHA"); sha != "" {
		return sha
	}
	cmd := exec.Command("git", "rev-parse", "HEAD")
	out, err := cmd.Output()
	if err != nil {
		t.Logf("revision unavailable: %v", err)
		return "unknown"
	}
	return strings.TrimSpace(string(out))
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
