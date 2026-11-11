package simulation

import (
	"fmt"
	"testing"
)

func TestFirstContactSmoke(t *testing.T) {
	t.Parallel()
	shardCase(t)
	exercise(t, 367, Plan{Devices: 5, Clock: "frozen", Scenario: "first-contact-cold"})
}

func TestFirstContactClocks(t *testing.T) {
	t.Parallel()
	exploration(t)
	for _, devices := range []int{5, 6, 11} {
		for _, clock := range []string{"", "frozen", "backward", "skewed"} {
			for _, cache := range []string{"warm", "cold"} {
				t.Run(fmt.Sprintf("devices-%d/%s/%s", devices, clock, cache), func(t *testing.T) {
					t.Parallel()
					shardCase(t)
					exercise(t, 367, Plan{Devices: devices, Clock: clock, Scenario: "first-contact-" + cache})
				})
			}
		}
	}
}
