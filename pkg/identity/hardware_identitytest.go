//go:build identitytest

package identity

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/google/go-tpm/tpm2/transport"
)

// Software transport is compiled only into the explicit identitytest CLI.
// Even that binary refuses non-loopback endpoints.
func platformHardware() HardwareBackend {
	endpoint := os.Getenv("ENBU_TEST_TPM_URL")
	return &TPMBackend{Device: "test-only vTPM", Open: func() (transport.TPMCloser, error) {
		u, err := url.Parse(endpoint)
		if err != nil || u.Scheme != "http" || (u.Hostname() != "127.0.0.1" && u.Hostname() != "::1") {
			return nil, errors.New("test TPM requires an HTTP loopback endpoint")
		}
		return &loopbackTPM{endpoint: endpoint, client: &http.Client{Timeout: 10 * time.Second}}, nil
	}}
}

type loopbackTPM struct {
	endpoint string
	client   *http.Client
}

func (t *loopbackTPM) Send(command []byte) ([]byte, error) {
	resp, err := t.client.Post(t.endpoint, "application/octet-stream", bytes.NewReader(command))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("test TPM HTTP status %d", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if len(b) < 10 || int(binary.BigEndian.Uint32(b[2:6])) != len(b) {
		return nil, errors.New("invalid test TPM response")
	}
	return b, nil
}
func (t *loopbackTPM) Close() error { t.client.CloseIdleConnections(); return nil }
