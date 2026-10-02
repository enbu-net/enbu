//go:build identitye2e

package identitye2e

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"sync"
	"testing"

	vtpm "github.com/deploymenttheory/go-sdk-vtpm2/tpm2"
	"github.com/google/go-tpm/tpm2"
)

type sdkTransport struct{ t *vtpm.TPM }

func (t sdkTransport) Send(b []byte) ([]byte, error) { return t.t.Execute(b), nil }

// TestVTPMProcess is a subprocess fixture. It persists SDK state after every
// command, then the harness kills and starts a new process from that state.
func TestVTPMProcess(t *testing.T) {
	path := os.Getenv("ENBU_VTPM_PROCESS_STATE")
	if path == "" {
		return
	}
	v := vtpm.New()
	if b, err := os.ReadFile(path); err == nil {
		var snapshot vtpm.Snapshot
		if err := json.Unmarshal(b, &snapshot); err != nil {
			t.Fatal(err)
		}
		if err := v.Restore(snapshot); err != nil {
			t.Fatal(err)
		}
	} else if !os.IsNotExist(err) {
		t.Fatal(err)
	} else {
		if _, err := (tpm2.Startup{StartupType: tpm2.TPMSUClear}).Execute(sdkTransport{v}); err != nil {
			t.Fatal(err)
		}
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println("http://" + l.Addr().String())
	var mu sync.Mutex
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		command, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		response := v.Execute(command)
		b, err := json.Marshal(v.Snapshot())
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		if err := os.WriteFile(path+".tmp", b, 0o600); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		if err := os.Rename(path+".tmp", path); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		_, _ = w.Write(response)
	})}
	if err := server.Serve(l); err != nil {
		t.Fatal(err)
	}
}

func startVTPM(t *testing.T, path string) (string, func()) {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestVTPMProcess$")
	cmd.Env = append(os.Environ(), "ENBU_VTPM_PROCESS_STATE="+path)
	cmd.Stderr = os.Stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	r := bufio.NewReader(stdout)
	endpoint, err := r.ReadString('\n')
	if err != nil {
		_ = cmd.Process.Kill()
		t.Fatal(err)
	}
	var once sync.Once
	stop := func() { once.Do(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }) }
	t.Cleanup(stop)
	return endpoint[:len(endpoint)-1], stop
}
