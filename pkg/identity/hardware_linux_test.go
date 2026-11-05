//go:build linux && !identitytest

package identity

import (
	"errors"
	"github.com/enbu-net/enbu/pkg/clock"
	"io/fs"
	"os"
	"strings"
	"testing"
)

func TestExplainTPMOpenError(t *testing.T) {
	if explainTPMOpenError(nil) != nil {
		t.Fatal("nil error must stay nil")
	}
	denied := &os.PathError{Op: "open", Path: tpmDevice, Err: fs.ErrPermission}
	err := explainTPMOpenError(denied)
	if !errors.Is(err, fs.ErrPermission) || !strings.Contains(err.Error(), "usermod -aG tss") {
		t.Fatalf("permission error = %v, want the cause and the tss hint", err)
	}
	missing := &os.PathError{Op: "open", Path: tpmDevice, Err: fs.ErrNotExist}
	if err := explainTPMOpenError(missing); !errors.Is(err, fs.ErrNotExist) || !strings.Contains(err.Error(), "resource manager") {
		t.Fatalf("missing device error = %v", err)
	}
	other := errors.New("boom")
	if explainTPMOpenError(other) != other {
		t.Fatal("other errors must pass through unchanged")
	}
}

func TestPlatformHardwareUsesResourceManager(t *testing.T) {
	b, ok := platformHardware(clock.New()).(*TPMBackend)
	if !ok || b.Device != "/dev/tpmrm0" {
		t.Fatalf("platformHardware(clock.New()) = %#v, want the TPM backend on /dev/tpmrm0", platformHardware(clock.New()))
	}
}
