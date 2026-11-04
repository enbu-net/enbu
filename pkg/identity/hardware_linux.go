//go:build linux && !identitytest

package identity

import (
	"errors"
	"fmt"
	"io/fs"

	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/linuxtpm"
)

// tpmDevice is the kernel's TPM resource manager. The raw /dev/tpm0 is not
// used: it admits one process at a time, bypasses the resource manager that
// tpm2-abrmd and other users rely on, and keeps transient objects loaded if
// enbu dies. Every kernel since 4.12 has the resource manager.
const tpmDevice = "/dev/tpmrm0"

func platformHardware() HardwareBackend {
	return &TPMBackend{Device: tpmDevice, Open: func() (transport.TPMCloser, error) {
		t, err := linuxtpm.Open(tpmDevice)
		return t, explainTPMOpenError(err)
	}}
}

// explainTPMOpenError says how to fix the usual reasons the TPM cannot be
// opened. Distributions give /dev/tpmrm0 to the tss group (mode 0660), so a
// user outside it falls back to the OS keyring until added.
func explainTPMOpenError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, fs.ErrPermission):
		return fmt.Errorf("%w; to use the TPM, add your user to the tss group (sudo usermod -aG tss $USER) and log in again", err)
	case errors.Is(err, fs.ErrNotExist):
		return fmt.Errorf("%w; no TPM 2.0 resource manager found", err)
	}
	return err
}
