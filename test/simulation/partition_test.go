package simulation

import (
	"fmt"
	"hash/fnv"
	"os"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

// Sampling uses the upper hash bits so it does not select just one lane when
// lane assignment and sample stride are both powers of two.
func caseInSample(name string, stride, phase int) (bool, error) {
	if stride < 1 || phase < 0 || phase >= stride {
		return false, fmt.Errorf("invalid simulation sample %d/%d", phase, stride)
	}
	top, _, _ := strings.Cut(name, "/")
	if top == "TestSimulation" || top == "TestScenarios" || strings.Contains(top, "Smoke") {
		return true, nil
	}
	h := fnv.New64a()
	_, _ = h.Write([]byte(name))
	return int((h.Sum64()>>32)%uint64(stride)) == phase, nil
}

func sampleCase(t *testing.T) {
	t.Helper()
	stride := integer(t, "ENBU_SIM_CASE_STRIDE", 1)
	if stride == 1 {
		return
	}
	h := fnv.New64a()
	_, _ = h.Write([]byte(revision(t)))
	phase := int(h.Sum64() % uint64(stride))
	selected, err := caseInSample(t.Name(), stride, phase)
	if err != nil {
		t.Fatal(err)
	}
	if !selected {
		t.Skipf("incremental sample %d/%d; daily exploration runs every case", phase, stride)
	}
}

func TestIncrementalSamplesRetainFullExploration(t *testing.T) {
	counts := make([]int, 4)
	for i := range 4096 {
		name := fmt.Sprintf("TestMatrix/devices-%d/clock-%d/case-%d", i%7+2, i%4, i)
		owners := 0
		for phase := range 8 {
			selected, err := caseInSample(name, 8, phase)
			if err != nil {
				t.Fatal(err)
			}
			if !selected {
				continue
			}
			owners++
			if phase == 0 {
				for lane := range 4 {
					if assigned, _ := caseOnLane(name, 4, lane); assigned {
						counts[lane]++
					}
				}
			}
		}
		if owners != 1 {
			t.Fatalf("case belongs to %d samples", owners)
		}
		if full, err := caseInSample(name, 1, 0); err != nil || !full {
			t.Fatal("full exploration omitted a case")
		}
	}
	for lane, count := range counts {
		if count < 64 || count > 256 {
			t.Fatalf("sample is unbalanced across lanes: lane=%d count=%d", lane, count)
		}
	}
	for _, name := range []string{"TestSimulation/seed-1", "TestScenarios/wire-format-cold", "TestAuthorityAttackSmoke/attack"} {
		for phase := range 8 {
			if selected, err := caseInSample(name, 8, phase); err != nil || !selected {
				t.Fatalf("sampling omitted required smoke/workload %s", name)
			}
		}
	}
	for _, invalid := range [][2]int{{0, 0}, {8, -1}, {8, 8}} {
		if _, err := caseInSample("case", invalid[0], invalid[1]); err == nil {
			t.Fatalf("invalid sample accepted: %v", invalid)
		}
	}
}

// New finite matrices must divide their named cases too: dividing only random
// seeds repeats expensive durable-file workflows on every native Actions lane.
func caseOnLane(name string, lanes, lane int) (bool, error) {
	if lanes < 1 || lane < 0 || lane >= lanes {
		return false, fmt.Errorf("invalid simulation lane %d/%d", lane, lanes)
	}
	h := fnv.New64a()
	_, _ = h.Write([]byte(name))
	return int(h.Sum64()%uint64(lanes)) == lane, nil
}

func shardCase(t *testing.T) {
	t.Helper()
	lanes := integer(t, "ENBU_SIM_SHARDS", 1)
	lane := 0
	if raw := os.Getenv("ENBU_SIM_SHARD"); raw != "" {
		var err error
		lane, err = strconv.Atoi(raw)
		if err != nil {
			t.Fatal("invalid simulation lane")
		}
	} else if lanes > 1 {
		t.Fatal("ENBU_SIM_SHARD is required with multiple lanes")
	}
	selected, err := caseOnLane(t.Name(), lanes, lane)
	if err != nil {
		t.Fatal(err)
	}
	if !selected {
		t.Skip("case assigned to another simulation lane")
	}
}

// Consecutive groups of equally expensive worlds must not cluster on one lane.
// In particular, each actor-count block in the large-team matrix costs much
// more than the preceding one on Windows' durable filesystem operations.
func indexedCaseOwner(index, lanes, stride int) (lane, phase int, err error) {
	if index < 0 || lanes < 1 || stride < 1 {
		return 0, 0, fmt.Errorf("invalid indexed simulation partition")
	}
	return index % lanes, (index / lanes) % stride, nil
}

func indexedCase(t *testing.T, index int) {
	t.Helper()
	lanes := integer(t, "ENBU_SIM_SHARDS", 1)
	lane := 0
	if raw := os.Getenv("ENBU_SIM_SHARD"); raw != "" {
		var err error
		lane, err = strconv.Atoi(raw)
		if err != nil || lane < 0 || lane >= lanes {
			t.Fatal("invalid simulation lane")
		}
	} else if lanes > 1 {
		t.Fatal("ENBU_SIM_SHARD is required with multiple lanes")
	}
	stride := integer(t, "ENBU_SIM_CASE_STRIDE", 1)
	owner, phase, err := indexedCaseOwner(index, lanes, stride)
	if err != nil {
		t.Fatal(err)
	}
	h := fnv.New64a()
	_, _ = h.Write([]byte(revision(t)))
	if owner != lane || phase != int(h.Sum64()%uint64(stride)) {
		t.Skip("case assigned to another simulation lane or sample")
	}
	// The index has selected the sample already; exercise must not re-sample
	// the same world using its name and accidentally omit it from every phase.
	t.Setenv("ENBU_SIM_CASE_STRIDE", "1")
}

func TestLargeTeamPartitionsAreCompleteAndBalanced(t *testing.T) {
	for _, stride := range []int{1, 8} {
		counts := make([][3]int, 4*stride)
		for index := range 252 {
			lane, phase, err := indexedCaseOwner(index, 4, stride)
			if err != nil {
				t.Fatal(err)
			}
			counts[phase*4+lane][index/84]++
		}
		for phase := range stride {
			for actors := range 3 {
				for lane := range 4 {
					if counts[phase*4+lane][actors] != counts[phase*4][actors] {
						t.Fatalf("unbalanced actors=%d phase=%d: %v", actors, phase, counts)
					}
				}
			}
		}
	}
	for _, invalid := range [][3]int{{-1, 4, 8}, {0, 0, 8}, {0, 4, 0}} {
		if _, _, err := indexedCaseOwner(invalid[0], invalid[1], invalid[2]); err == nil {
			t.Fatalf("invalid indexed partition accepted: %v", invalid)
		}
	}
}

func TestIndexedCaseDoesNotResampleByName(t *testing.T) {
	const revision = "indexed-partition"
	t.Setenv("GITHUB_SHA", revision)
	t.Setenv("ENBU_SIM_SHARDS", "4")
	t.Setenv("ENBU_SIM_SHARD", "0")
	t.Setenv("ENBU_SIM_CASE_STRIDE", "8")
	h := fnv.New64a()
	_, _ = h.Write([]byte(revision))
	phase := int(h.Sum64() % 8)
	for i := range 100 {
		name := fmt.Sprint(i)
		selected, err := caseInSample(t.Name()+"/"+name, 8, phase)
		if err != nil {
			t.Fatal(err)
		}
		if selected {
			continue
		}
		executed := false
		t.Run(name, func(t *testing.T) {
			indexedCase(t, phase*4)
			sampleCase(t)
			executed = true
		})
		if !executed {
			t.Fatal("index-selected case was omitted by name sampling")
		}
		return
	}
	t.Fatal("could not find a case outside the name sample")
}

func TestNamedCasePartitionIsCompleteAndDisjoint(t *testing.T) {
	for _, lanes := range []int{1, 4, 15, 32} {
		counts := make([]int, lanes)
		for i := 0; i < 1000; i++ {
			name := fmt.Sprintf("matrix/devices-%d/clock-%d/case-%d", i%7+2, i%4, i)
			owners := 0
			for lane := range lanes {
				selected, err := caseOnLane(name, lanes, lane)
				if err != nil {
					t.Fatal(err)
				}
				if selected {
					owners++
					counts[lane]++
				}
			}
			if owners != 1 {
				t.Fatalf("%s assigned to %d of %d lanes", name, owners, lanes)
			}
		}
		for lane, count := range counts {
			if count < 500/lanes || count > 2000/lanes {
				t.Fatalf("lane %d/%d has an unbalanced workload: %d of 1000 cases", lane, lanes, count)
			}
		}
	}
	for _, dimensions := range [][2]int{{0, 0}, {4, -1}, {4, 4}, {1, 1}} {
		if _, err := caseOnLane("case", dimensions[0], dimensions[1]); err == nil {
			t.Fatalf("invalid lane accepted: %v", dimensions)
		}
	}
}

func TestSeedPartitionPreservesWorkload(t *testing.T) {
	collect := func(shards, seeds int) map[uint64]bool {
		out := map[uint64]bool{}
		for shard := range shards {
			for i := range seeds {
				seed := simulationSeed(i, shards, shard, "same-commit")
				if out[seed] {
					t.Fatalf("duplicated seed %d", seed)
				}
				out[seed] = true
			}
		}
		return out
	}
	old, previous, current := collect(8, 128), collect(4, 256), collect(16, 64)
	if len(current) != 1024 || !reflect.DeepEqual(current, old) || !reflect.DeepEqual(current, previous) {
		t.Fatal("repartitioning changed the explored workloads")
	}
}

func TestMutationPartitionCoversAllExperiments(t *testing.T) {
	counts := make([]int, 4)
	seen := make(map[string]bool)
	for _, experiment := range mutationCases {
		if seen[experiment.name] {
			t.Fatalf("duplicate mutation name %q", experiment.name)
		}
		seen[experiment.name] = true
		owners := 0
		for lane := range 4 {
			selected, err := caseOnLane("TestOracleMutationExperiments/"+experiment.name, 4, lane)
			if err != nil {
				t.Fatal(err)
			}
			if selected {
				owners++
				counts[lane]++
			}
		}
		if owners != 1 {
			t.Fatalf("mutation %s has %d owners", experiment.name, owners)
		}
	}
	for lane, count := range counts {
		if count == 0 || count > (len(mutationCases)+1)/2 {
			t.Fatalf("unbalanced mutation lane %d: %d", lane, count)
		}
	}
}
