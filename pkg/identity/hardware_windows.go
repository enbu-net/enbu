//go:build windows && !identitytest

package identity

import "github.com/google/go-tpm/tpm2/transport/windowstpm"

func platformHardware() HardwareBackend {
	return &TPMBackend{Device: "Windows TBS", Open: windowstpm.Open}
}
