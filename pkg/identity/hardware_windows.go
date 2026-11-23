//go:build windows && !identitytest

package identity

import (
	"errors"
	"fmt"
	"io/fs"

	"github.com/enbu-net/enbu/pkg/clock"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/windowstpm"
	"github.com/google/go-tpm/tpmutil/tbs"
)

func platformHardware(c clock.Clock) HardwareBackend {
	return &TPMBackend{Device: "Windows TBS", Open: func() (transport.TPMCloser, error) {
		t, err := windowstpm.Open()
		if err != nil {
			return nil, explainTBSOpenError(err)
		}
		return tbsTransport{t}, nil
	}}
}

func explainTBSOpenError(err error) error {
	switch {
	case errors.Is(err, windowstpm.ErrNotTPM20), errors.Is(err, tbs.ErrTPMNotFound):
		return fmt.Errorf("%w: %w", fs.ErrNotExist, err)
	case errors.Is(err, tbs.ErrAccessDenied):
		return fmt.Errorf("%w: %w", fs.ErrPermission, err)
	}
	return err
}

type tbsTransport struct{ transport.TPMCloser }

func (t tbsTransport) Send(command []byte) ([]byte, error) {
	response, err := t.TPMCloser.Send(command)
	if errors.Is(err, tbs.ErrAccessDenied) {
		err = fmt.Errorf("%w: %w", fs.ErrPermission, err)
	}
	return response, err
}
