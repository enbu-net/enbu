//go:build windows && !identitytest

package identity

import (
	"github.com/enbu-net/enbu/pkg/clock"
	"github.com/google/go-tpm/tpm2/transport/windowstpm"
)

func platformHardware(c clock.Clock) HardwareBackend {
	return &TPMBackend{Clock: c, Device: "Windows TBS", Open: windowstpm.Open, Verifier: newHelloVerifier()}
}
