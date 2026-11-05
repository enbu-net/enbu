package simulation

import (
	"fmt"
	"os"
	"strconv"
	"testing"
)

func TestCompoundMultiUserMatrix(t *testing.T) {
	exploration(t)
	index := 0
	for _, control := range []string{"remove-writer", "demote-admin"} {
		for _, fault := range []string{"crash-before", "crash-after", "after"} {
			for _, resolution := range []string{"same", "different", "delete"} {
				index++
				if os.Getenv("ENBU_SIM_SHARDS") != "" {
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
					t.Run(fmt.Sprintf("%s/%s/%s/seed-%d", control, fault, resolution, seed), func(t *testing.T) {
						exercise(t, seed, Plan{Devices: 4, Compound: &CompoundCase{Control: control, Fault: fault, Resolution: resolution}})
					})
				}
			}
		}
	}
}
