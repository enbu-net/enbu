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
	old, previous, current := collect(8, 128), collect(32, 32), collect(4, 256)
	if len(current) != 1024 || !reflect.DeepEqual(current, old) || !reflect.DeepEqual(current, previous) {
		t.Fatal("repartitioning changed the explored workloads")
	}
}
