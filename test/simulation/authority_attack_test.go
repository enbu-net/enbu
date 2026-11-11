package simulation

import (
	"fmt"
	"testing"
)

func TestAuthorityAttackSmoke(t *testing.T) {
	t.Parallel()
	for _, attack := range AuthorityAttacks {
		t.Run(attack, func(t *testing.T) { exercise(t, 37, Plan{Devices: 3, AuthorityAttack: attack}) })
	}
}
func TestAuthorityAttackMatrix(t *testing.T) {
	t.Parallel()
	exploration(t)
	index := 0
	for _, attack := range AuthorityAttacks {
		for _, profile := range []string{"", "frozen", "backward", "skewed"} {
			for seed := uint64(0); seed < 4; seed++ {
				index++
				if !ownsIndex(t, index-1) {
					continue
				}
				t.Run(fmt.Sprintf("%s/%s/seed-%d", attack, profile, seed), func(t *testing.T) { exercise(t, seed, Plan{Devices: 3, Clock: profile, AuthorityAttack: attack}) })
			}
		}
	}
}
