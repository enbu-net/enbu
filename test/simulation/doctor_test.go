package simulation

import "testing"

// The public-surface driver checks diagnosis health and read-only storage access;
// exercise also strictly replays every diagnostic read and the resulting report.
func TestDoctorSimulationSmoke(t *testing.T) {
	t.Parallel()
	exercise(t, 127, Plan{Devices: 3, Clock: "frozen", Scenario: "public-surface"})
}
