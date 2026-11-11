package simulation

import (
	"fmt"
	"testing"
)

func TestRetainedObserverSmoke(t *testing.T) {
	t.Parallel()
	shardCase(t)
	exercise(t, 379, Plan{Devices: 3, Scenario: "retained-observer-delete-cold"})
}

func TestRetainedObserverClocks(t *testing.T) {
	t.Parallel()
	exploration(t)
	for _, devices := range []int{3, 4, 8} {
		for _, clock := range []string{"", "frozen", "backward", "skewed"} {
			for _, choice := range []string{"value", "delete"} {
				for _, cache := range []string{"warm", "cold"} {
					t.Run(fmt.Sprintf("devices-%d/%s/%s/%s", devices, clock, choice, cache), func(t *testing.T) {
						t.Parallel()
						shardCase(t)
						exercise(t, 379, Plan{Devices: devices, Clock: clock, Scenario: "retained-observer-" + choice + "-" + cache})
					})
				}
			}
		}
	}
}
