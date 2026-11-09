package simulation

import (
	"fmt"
	"testing"
)

func TestConcurrentHistoryRestore(t *testing.T) {
	exploration(t)
	index := 0
	for _, right := range []string{"edit", "delete", "import", "sync", "restore", "compact"} {
		for _, same := range []bool{false, true} {
			// Both restores address the same historical snapshot, whose only
			// difference from the current state is K0.
			if right == "restore" && !same {
				continue
			}
			if right == "compact" && same {
				continue // Compaction addresses history, rather than a key.
			}
			index++
			if !ownsIndex(t, index-1) {
				continue
			}
			for seed := uint64(0); seed < 4; seed++ {
				t.Run(fmt.Sprintf("restore/%s/same-%t/seed-%d", right, same, seed), func(t *testing.T) {
					exercise(t, seed, Plan{Devices: 3, Concurrent: &ConcurrentCase{Left: "restore", Right: right, SameKey: same}})
				})
			}
		}
	}
}
