package simulation

import (
	"fmt"
	"testing"
)

func TestObserverControlEquivocationSmoke(t *testing.T) {
	shardCase(t)
	exercise(t, 359, Plan{Devices: 4, Clock: "frozen", Scenario: "observer-control-cold"})
}

func TestObserverControlEquivocationClocks(t *testing.T) {
	exploration(t)
	for _, devices := range []int{4, 5, 8} {
		for _, clock := range []string{"", "frozen", "backward", "skewed"} {
			for _, cache := range []string{"warm", "cold"} {
				t.Run(fmt.Sprintf("devices-%d/%s/%s", devices, clock, cache), func(t *testing.T) {
					shardCase(t)
					exercise(t, 359, Plan{Devices: devices, Clock: clock, Scenario: "observer-control-" + cache})
				})
			}
		}
	}
}
