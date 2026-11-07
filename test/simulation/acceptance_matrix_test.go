package simulation

import (
	"fmt"
	"os"
	"strconv"
	"testing"
)

func TestAcceptanceEpochSurvivesReadmissionAndAuthorRemoval(t *testing.T) {
	exploration(t)
	index := 0
	for _, profile := range []string{"", "frozen", "backward", "skewed"} {
		for _, admin := range []bool{false, true} {
			for _, after := range []bool{false, true} {
				for _, restart := range []bool{false, true} {
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
						t.Run(fmt.Sprintf("%s/admin-%t/accepted-after-%t/restart-%t/seed-%d", profile, admin, after, restart, seed), func(t *testing.T) {
							exercise(t, seed, Plan{Devices: 3, Clock: profile, Acceptance: &AcceptanceCase{AfterReadmission: after, Restart: restart, Admin: admin}})
						})
					}
				}
			}
		}
	}
}

func TestAcceptanceEpochSmoke(t *testing.T) {
	for _, after := range []bool{false, true} {
		t.Run(fmt.Sprintf("accepted-after-%t", after), func(t *testing.T) {
			exercise(t, 17, Plan{Devices: 3, Acceptance: &AcceptanceCase{AfterReadmission: after, Restart: true}})
		})
	}
}
