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
	shardCase(t)
	exercise(t, 3, Plan{Devices: 3, Actions: Generate(3, 32, 3)})
}

// CI seed 17913170502171862805 reduced to these four operations. An
// observer had accepted the synchronizer's pre-removal head, which remained
// a sibling even though every observer initially read the same plaintext.
func TestGeneratedTeamGroupRetiredObserverSmoke(t *testing.T) {
	shardCase(t)
	exercise(t, 17913170502171862805, Plan{
		Devices: 8, Scenario: "output-boundary-upgraded-preserve-hardlink",
		Actions: []Action{
			{Kind: "create-env", Device: 1, Environment: "env_2"},
			{Kind: "parallel", Device: 6, Parallel: &ConcurrentCase{Left: "delete", Right: "import", SameKey: true, Devices: []int{0, 2}}},
			{Kind: "team-group", Device: 1, Key: "TEAM_v_15_9580284031657808576", Value: "v_15_9580284031657808576"},
			{Kind: "parallel", Parallel: &ConcurrentCase{Left: "delete", Right: "import", Devices: []int{3, 2}}},
		},
	})
}

func TestGeneratedTeamGroupCISeed(t *testing.T) {
	exploration(t)
	shardCase(t)
	const seed = 17913170502171862805
	exercise(t, seed, Plan{Devices: 8, Scenario: "output-boundary-upgraded-preserve-hardlink", Actions: Generate(seed, 32, 8)})
}
