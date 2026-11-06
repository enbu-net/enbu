package simulation

import (
	"fmt"
	"testing"
)

func TestObserverEquivocationSmoke(t *testing.T) {
	for _, mode := range []string{"disjoint", "conflict"} {
		t.Run(mode, func(t *testing.T) {
			shardCase(t)
			exercise(t, 353, Plan{Devices: 3, Scenario: "observer-state-" + mode + "-cold"})
		})
	}
}

func TestObserverEquivocationClocks(t *testing.T) {
	exploration(t)
	for _, devices := range []int{3, 4, 8} {
		for _, clock := range []string{"", "frozen", "backward", "skewed"} {
			for _, mode := range []string{"disjoint", "conflict"} {
				for _, cache := range []string{"warm", "cold"} {
					t.Run(fmt.Sprintf("devices-%d/%s/%s/%s", devices, clock, mode, cache), func(t *testing.T) {
						shardCase(t)
						exercise(t, 353, Plan{Devices: devices, Clock: clock, Scenario: "observer-state-" + mode + "-" + cache})
					})
				}
			}
		}
	}
}
