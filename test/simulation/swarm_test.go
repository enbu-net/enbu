package simulation

import (
	"fmt"
	"os"
	"strconv"
	"testing"
)

func TestMultiUserSwarmMatrix(t *testing.T) {
	index := 0
	for devices := 3; devices <= 8; devices++ {
		for _, scene := range []string{"disjoint-add", "disjoint-mixed", "identical-edit", "identical-delete", "distinct-edit", "edit-delete", "conflicting-import", "offline-observer"} {
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
				t.Run(fmt.Sprintf("devices-%d/%s/seed-%d", devices, scene, seed), func(t *testing.T) {
					exercise(t, seed, Plan{Devices: devices, Swarm: scene})
				})
			}
		}
	}
}
