package simulation

import (
	"fmt"
	"os"
	"strconv"
	"testing"
)

func TestCompactionLatePublicationAndCrashRecovery(t *testing.T) {
	exploration(t)
	index := 0
	for _, publication := range []string{"valid", "junk", "missing", "corrupt", "offline", "cancelled"} {
		for _, fault := range []string{"", "before", "after", "cancel", "crash-before", "crash-after"} {
			if (publication == "offline" || publication == "cancelled") && fault != "" {
				continue
			}
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
				t.Run(fmt.Sprintf("%s/%s/seed-%d", publication, fault, seed), func(t *testing.T) {
					exercise(t, seed, Plan{Devices: 3, CompactionRace: &CompactionRaceCase{Publication: publication, Fault: fault}})
				})
			}
		}
	}
}
