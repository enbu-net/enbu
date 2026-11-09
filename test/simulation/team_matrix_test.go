package simulation

import (
	"fmt"
	"testing"
)

func TestTeamMembershipWriteMatrix(t *testing.T) {
	exploration(t)
	for index, control := range TeamControls {
		if !ownsIndex(t, index) {
			continue
		}
		for _, write := range TeamWrites {
			for seed := uint64(0); seed < 4; seed++ {
				t.Run(fmt.Sprintf("%s/%s/seed-%d", control, write, seed), func(t *testing.T) {
					exercise(t, seed, Plan{Devices: 4, Team: &TeamCase{Control: control, Write: write}})
				})
			}
		}
	}
}
