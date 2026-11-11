package simulation

import (
	"fmt"
	"testing"
)

func TestConcurrentAdminMatrix(t *testing.T) {
	t.Parallel()
	exploration(t)
	for index, kind := range AdminRaces {
		if !ownsIndex(t, index) {
			continue
		}
		for seed := uint64(0); seed < 4; seed++ {
			t.Run(fmt.Sprintf("%s/seed-%d", kind, seed), func(t *testing.T) { exercise(t, seed, Plan{Devices: 5, AdminRace: kind}) })
		}
	}
}
