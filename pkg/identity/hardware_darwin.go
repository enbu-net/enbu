//go:build darwin && !identitytest

package identity

func platformHardware() HardwareBackend { return &enclaveBackend{} }
