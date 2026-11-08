package simulation

import (
	"fmt"
	"os"
	"strconv"
	"testing"
)

func TestAuthorityAttackSmoke(t *testing.T) {
	for _, attack := range AuthorityAttacks {
		t.Run(attack, func(t *testing.T) { exercise(t, 37, Plan{Devices: 3, AuthorityAttack: attack}) })
	}
}
func TestAuthorityAttackMatrix(t *testing.T) {
	exploration(t)
	index := 0
	for _, attack := range AuthorityAttacks {
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
				t.Run(fmt.Sprintf("%s/%s/seed-%d", attack, profile, seed), func(t *testing.T) { exercise(t, seed, Plan{Devices: 3, Clock: profile, AuthorityAttack: attack}) })
			}
		}
	}
}
