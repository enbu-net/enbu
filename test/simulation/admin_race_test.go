package simulation

import (
	"fmt"
	"os"
	"strconv"
	"testing"
)

func TestConcurrentAdminMatrix(t *testing.T) {
	exploration(t)
	for index, kind := range AdminRaces {
		if raw := os.Getenv("ENBU_SIM_SHARDS"); raw != "" {
			shards := integer(t, "ENBU_SIM_SHARDS", 1)
			shard, err := strconv.Atoi(os.Getenv("ENBU_SIM_SHARD"))
			if err != nil || shard < 0 || shard >= shards {
				t.Fatal("invalid shard")
			}
			if index%shards != shard {
				continue
			}
		}
		for seed := uint64(0); seed < 4; seed++ {
			t.Run(fmt.Sprintf("%s/seed-%d", kind, seed), func(t *testing.T) { exercise(t, seed, Plan{Devices: 5, AdminRace: kind}) })
		}
	}
}
