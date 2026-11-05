//go:build darwin && !identitytest

package identity

import "github.com/enbu-net/enbu/pkg/clock"

func platformHardware(c clock.Clock) HardwareBackend { return &enclaveBackend{Clock: c} }
