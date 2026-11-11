package simulation

import (
	"fmt"
	"testing"
)

func TestCompoundMultiUserMatrix(t *testing.T) {
	t.Parallel()
	exploration(t)
	index := 0
	for _, control := range []string{"remove-writer", "demote-admin"} {
		for _, fault := range []string{"crash-before", "crash-after", "after"} {
			for _, resolution := range []string{"same", "different", "delete"} {
				index++
				if !ownsIndex(t, index-1) {
					continue
				}
				for seed := uint64(0); seed < 4; seed++ {
					t.Run(fmt.Sprintf("%s/%s/%s/seed-%d", control, fault, resolution, seed), func(t *testing.T) {
						exercise(t, seed, Plan{Devices: 4, Compound: &CompoundCase{Control: control, Fault: fault, Resolution: resolution}})
					})
				}
			}
		}
	}
}
