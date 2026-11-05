package simulation

import (
	"fmt"
	"os"
	"strconv"
	"testing"
)

func TestGeneratedTeamGroupsPreservePriorWork(t *testing.T) {
	exploration(t)
	index := 0
	for devices := 3; devices <= 8; devices++ {
		for seed := uint64(0); seed < 4; seed++ {
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
			t.Run(fmt.Sprintf("devices-%d/seed-%d", devices, seed), func(t *testing.T) {
				actions := Generate(seed, 32, devices)
				groups := 0
				for _, action := range actions {
					if action.Kind == "team-group" {
						groups++
					}
				}
				if groups != 1 {
					t.Fatalf("generated %d team groups", groups)
				}
				exercise(t, seed, Plan{Devices: devices, Actions: actions})
			})
		}
	}
}

func TestGeneratedTeamGroupSmoke(t *testing.T) {
	exercise(t, 3, Plan{Devices: 3, Actions: Generate(3, 32, 3)})
}
