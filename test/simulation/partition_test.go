package simulation

import (
	"reflect"
	"testing"
)

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
	old, current := collect(8, 128), collect(32, 32)
	if len(current) != 1024 || !reflect.DeepEqual(current, old) {
		t.Fatal("repartitioning changed the explored workloads")
	}
}
