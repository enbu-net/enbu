package simulation

import (
	"fmt"
	"hash/fnv"
	"os"
	"reflect"
	"strconv"
	"testing"
)

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
