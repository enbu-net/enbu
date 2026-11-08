package simulation

import (
	"time"

	"github.com/jonboulle/clockwork"
)

// Wall-clock readings are pure. Only recorded storage boundaries advance the
// shared timer clock, so adding a Now call cannot change an operation's expiry.
// Clock skew changes a device's wall time without changing timer durations.
type deviceClock struct {
	*clockwork.FakeClock
	world           *World
	device, devices int
}

func (c deviceClock) Now() time.Time {
	base := time.Unix(1700000000, 0)
	elapsed := c.FakeClock.Now().Sub(base)
	switch c.world.Clock {
	case "frozen":
		return base
	case "backward":
		return base.Add(-elapsed)
	case "skewed":
		return base.Add(elapsed).Add(time.Duration(c.device-c.devices/2) * 365 * 24 * time.Hour)
	default:
		return base.Add(elapsed)
	}
}
