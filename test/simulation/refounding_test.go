package simulation

import (
	"fmt"
	"testing"
)

func TestRefoundingClockMatrix(t *testing.T) {
	t.Parallel()
	exploration(t)
	for _, devices := range []int{2, 3, 8} {
		for _, profile := range []string{"", "frozen", "backward", "skewed"} {
			t.Run(fmt.Sprintf("devices-%d/%s", devices, profile), func(t *testing.T) {
				t.Parallel()
				shardCase(t)
				exercise(t, 41, Plan{Devices: devices, Clock: profile, Scenario: "refounding", Actions: Generate(41, 32, devices)})
			})
		}
	}
}
