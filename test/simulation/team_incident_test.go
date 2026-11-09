package simulation

import (
	"fmt"
	"os"
	"strconv"
	"testing"
)

func TestTeamIncidentMatrix(t *testing.T) {
	exploration(t)
	index := 0
	for devices := 3; devices <= 8; devices++ {
		for _, profile := range []string{"", "frozen", "backward", "skewed"} {
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
				name := fmt.Sprintf("devices-%d/%s/seed-%d", devices, profile, seed)
				t.Run(name, func(t *testing.T) {
					exercise(t, seed, Plan{Devices: devices, Clock: profile, Scenario: "team-incident"})
				})
			}
		}
	}
}
