//go:build !linux && !windows && !darwin && !identitytest

package identity

func platformHardware() HardwareBackend { return nil }
