package simulation

import (
	"fmt"
	"os"
	"strconv"
	"testing"
)

func TestMultiUserClockProfiles(t *testing.T) {
	index := 0
	for _, clock := range []string{"frozen", "backward", "skewed"} {
		for _, scenario := range []string{"history", "key-update", "membership", "concurrent-keys", "conflicting-edits", "control-fork"} {
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
				t.Run(fmt.Sprintf("%s/%s/seed-%d", clock, scenario, seed), func(t *testing.T) {
					exercise(t, seed, Plan{Devices: 3, Clock: clock, Scenario: scenario})
				})
			}
		}
	}
}
