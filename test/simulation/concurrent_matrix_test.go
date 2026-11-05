package simulation

import (
	"fmt"
	"os"
	"strconv"
	"testing"
)

func TestConcurrentOperationMatrix(t *testing.T) {
	index := 0
	for _, left := range ConcurrentOperations {
		for _, right := range ConcurrentOperations {
			for _, same := range []bool{false, true} {
				index++
				if raw := os.Getenv("ENBU_SIM_SHARDS"); raw != "" {
					shards := integer(t, "ENBU_SIM_SHARDS", 1)
					shard, err := strconv.Atoi(os.Getenv("ENBU_SIM_SHARD"))
					if err != nil || shard < 0 || shard >= shards {
						t.Fatal("invalid shard")
					}
					if (index-1)%shards != shard {
						continue
					}
				}
				for seed := uint64(0); seed < 4; seed++ {
					t.Run(fmt.Sprintf("%s/%s/same-%t/seed-%d", left, right, same, seed), func(t *testing.T) {
						exercise(t, seed, Plan{Devices: 3, Concurrent: &ConcurrentCase{Left: left, Right: right, SameKey: same}})
					})
				}
			}
		}
	}
}
