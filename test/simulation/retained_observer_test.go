package simulation

import (
	"fmt"
	"testing"
)

func TestRetainedObserverSmoke(t *testing.T) {
	shardCase(t)
	exercise(t, 379, Plan{Devices: 3, Scenario: "retained-observer-cold"})
}

func TestRetainedObserverClocks(t *testing.T) {
	exploration(t)
	for _, devices := range []int{3, 4, 8} {
		for _, clock := range []string{"", "frozen", "backward", "skewed"} {
			for _, cache := range []string{"warm", "cold"} {
				t.Run(fmt.Sprintf("devices-%d/%s/%s", devices, clock, cache), func(t *testing.T) {
					shardCase(t)
					exercise(t, 379, Plan{Devices: devices, Clock: clock, Scenario: "retained-observer-" + cache})
				})
			}
		}
	}
}
