package simulation

import (
	"fmt"
	"testing"
)

func TestContentionClocks(t *testing.T) {
	exploration(t)
	for _, op := range contentionOperations {
		for _, outcome := range []string{"exhausted", "yield"} {
			for _, devices := range []int{2, 3, 8} {
				for _, profile := range []string{"", "frozen", "backward", "skewed"} {
					t.Run(fmt.Sprintf("%s-%s/devices-%d/%s", op, outcome, devices, profile), func(t *testing.T) {
						exercise(t, 73, Plan{Devices: devices, Clock: profile, Scenario: "contention-" + op + "-" + outcome})
					})
				}
			}
		}
	}
}
