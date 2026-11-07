package simulation

import (
	"fmt"
	"testing"
)

func TestStateSignatureAttackSmoke(t *testing.T) {
	for _, devices := range []int{2, 3, 8} {
		t.Run(fmt.Sprintf("devices-%d", devices), func(t *testing.T) {
			shardCase(t)
			exercise(t, 17121275537281659170, Plan{Devices: devices, Clock: "frozen", Scenario: "forged-state-signature"})
		})
	}
}

func TestFullSignatureAttackSeedRegressionSmoke(t *testing.T) {
	shardCase(t)
	const seed = uint64(17121275537281659170)
	const devices = 2
	exercise(t, seed, Plan{Devices: devices, Scenario: "forged-state-signature", Actions: Generate(seed, 256, devices)})
}
