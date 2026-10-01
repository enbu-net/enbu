//go:build linux && !identitytest

package identity

import (
	"os"

	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/linuxtpm"
)

func platformHardware() HardwareBackend {
	path := "/dev/tpmrm0"
	if _, err := os.Stat(path); os.IsNotExist(err) {
		path = "/dev/tpm0"
	}
	return &TPMBackend{Device: path, Open: func() (transport.TPMCloser, error) { return linuxtpm.Open(path) }}
}
