package simulation

import (
	"fmt"
	"testing"
)

func TestMultiUserSwarmMatrix(t *testing.T) {
	exploration(t)
	index := 0
	for devices := 3; devices <= 8; devices++ {
		for _, scene := range []string{"disjoint-add", "disjoint-mixed", "identical-edit", "identical-delete", "distinct-edit", "edit-delete", "conflicting-import", "offline-observer"} {
			index++
			if !ownsIndex(t, index-1) {
				continue
			}
			for seed := uint64(0); seed < 4; seed++ {
				t.Run(fmt.Sprintf("devices-%d/%s/seed-%d", devices, scene, seed), func(t *testing.T) {
					exercise(t, seed, Plan{Devices: devices, Swarm: scene})
				})
			}
		}
	}
}
