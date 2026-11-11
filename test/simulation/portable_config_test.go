package simulation

import (
	"fmt"
	"testing"
)

func TestPortableConfigClocks(t *testing.T) {
	t.Parallel()
	exploration(t)
	for _, devices := range []int{2, 3, 8} {
		for _, profile := range []string{"", "frozen", "backward", "skewed"} {
			t.Run(fmt.Sprintf("devices-%d/%s", devices, profile), func(t *testing.T) {
				t.Parallel()
				shardCase(t)
				exercise(t, 103, Plan{Devices: devices, Clock: profile, Scenario: "portable-config"})
			})
		}
	}
}
