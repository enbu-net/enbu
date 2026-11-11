package simulation

import (
	"fmt"
	"os"
	"testing"
)

func TestStateSignatureAttackSmoke(t *testing.T) {
	t.Parallel()
	for _, devices := range []int{2, 3, 8} {
		t.Run(fmt.Sprintf("devices-%d", devices), func(t *testing.T) {
			t.Parallel()
			shardCase(t)
			exercise(t, 17121275537281659170, Plan{Devices: devices, Clock: "frozen", Scenario: "forged-state-signature"})
		})
	}
}

func TestFullSignatureAttackSeedRegressionSmoke(t *testing.T) {
	t.Parallel()
	// Bounded two-device smoke above catches the original panic in unit and
	// instrumented coverage. Keep the 256-operation replay in native DST, where
	// it is mandatory in every selected incremental and full exploration.
	if os.Getenv("ENBU_SIM_EXPLORE") != "1" {
		t.Skip("long seed regression runs in dedicated native DST")
	}
	shardCase(t)
	const seed = uint64(17121275537281659170)
	const devices = 2
	exercise(t, seed, Plan{Devices: devices, Scenario: "forged-state-signature", Actions: Generate(seed, 256, devices)})
}
