package simulation

import (
	"fmt"
	"testing"
)

func TestTeamIncidentMatrix(t *testing.T) {
	exploration(t)
	index := 0
	for devices := 3; devices <= 8; devices++ {
		for _, profile := range []string{"", "frozen", "backward", "skewed"} {
			for seed := uint64(0); seed < 4; seed++ {
				index++
				if !ownsIndex(t, index-1) {
					continue
				}
				name := fmt.Sprintf("devices-%d/%s/seed-%d", devices, profile, seed)
				t.Run(name, func(t *testing.T) {
					exercise(t, seed, Plan{Devices: devices, Clock: profile, Scenario: "team-incident"})
				})
			}
		}
	}
}
