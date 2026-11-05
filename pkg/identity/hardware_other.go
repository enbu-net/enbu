//go:build !linux && !windows && !darwin && !identitytest

package identity

import "github.com/enbu-net/enbu/pkg/clock"

func platformHardware(c clock.Clock) HardwareBackend { return nil }
