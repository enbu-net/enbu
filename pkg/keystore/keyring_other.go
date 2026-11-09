//go:build !linux

package keystore

import (
	"context"
	"errors"

	"github.com/zalando/go-keyring"
)

// checkBeforeUse is false: macOS Keychain and Windows Credential Manager do
// not wait on an unlock prompt the way a locked Secret Service does.
const checkBeforeUse = false

// probeKeyring is replaced in tests.
var probeKeyring = probeByLookup

// probeByLookup looks up a missing entry. It is the probe on macOS and
// Windows, whose keyrings answer without a prompt. The lookup cannot be
// cancelled, so a hung one is left behind and the probe reports a timeout.
func probeByLookup(ctx context.Context) error {
	ch := make(chan error, 1)
	go func() {
		_, err := keyring.Get("enbu-probe", "probe")
		if errors.Is(err, keyring.ErrNotFound) {
			err = nil
		}
		ch <- err
	}()
	select {
	case err := <-ch:
		return err
	case <-ctx.Done():
		return errors.New("keyring unavailable: timed out")
	}
}
