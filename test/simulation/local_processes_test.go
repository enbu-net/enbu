package simulation

import (
	"fmt"
	"testing"
)

func TestSameUserProcessClocks(t *testing.T) {
	exploration(t)
	for _, profile := range []string{"", "frozen", "backward", "skewed"} {
		for seed := uint64(0); seed < 4; seed++ {
			t.Run(fmt.Sprintf("%s/seed-%d", profile, seed), func(t *testing.T) {
				exercise(t, seed, Plan{Devices: 3, Clock: profile, Scenario: "same-user-processes"})
			})
		}
	}
}
