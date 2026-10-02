//go:build identitye2e

package identitye2e

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	agecrypto "filippo.io/age"
	"github.com/enbu-net/enbu/pkg/age"
	"github.com/enbu-net/enbu/pkg/identity"
	"github.com/enbu-net/enbu/pkg/oci"
	"github.com/zalando/go-keyring"
)

type cliHarness struct {
	t           *testing.T
	binary, dir string
	env         map[string]string
}

func (h *cliHarness) process(args ...string) ([]byte, []byte, error) {
	h.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, h.binary, args...)
	cmd.Dir = h.dir
	for _, entry := range os.Environ() {
		name, _, _ := strings.Cut(entry, "=")
		if _, overridden := h.env[name]; !overridden {
			cmd.Env = append(cmd.Env, entry)
		}
	}
	for name, value := range h.env {
		cmd.Env = append(cmd.Env, name+"="+value)
	}
	var out, stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr
	err := cmd.Run()
	return out.Bytes(), stderr.Bytes(), err
}

func (h *cliHarness) run(args ...string) map[string]any {
	h.t.Helper()
	args = append(args, "--json")
	out, stderr, err := h.process(args...)
	if err != nil {
		h.t.Fatalf("CLI %v: %v\nstdout: %s\nstderr: %s", args, err, out, stderr)
	}
	if len(stderr) != 0 {
		h.t.Fatalf("JSON CLI wrote stderr: %s", stderr)
	}
	var envelope map[string]any
	if err := json.Unmarshal(out, &envelope); err != nil {
		h.t.Fatalf("invalid JSON: %s %v", out, err)
	}
	if envelope["ok"] != true {
		h.t.Fatalf("unsuccessful envelope: %s", out)
	}
	data, ok := envelope["data"].(map[string]any)
	if !ok {
		h.t.Fatalf("unexpected data: %s", out)
	}
	return data
}

func (h *cliHarness) fails(args ...string) {
	h.t.Helper()
	out, _, err := h.process(append(args, "--json")...)
	if err == nil {
		h.t.Fatalf("CLI succeeded unexpectedly: %v", args)
	}
	var envelope map[string]any
	if err := json.Unmarshal(out, &envelope); err != nil || envelope["ok"] != false {
		h.t.Fatalf("missing JSON error: %s %v", out, err)
	}
}

func newHarness(t *testing.T, binary, backend string) *cliHarness {
	t.Helper()
	dir := t.TempDir()
	for _, args := range [][]string{{"init"}, {"remote", "add", "origin", "https://github.com/e2e/identity.git"}} {
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git: %s %v", out, err)
		}
	}
	return &cliHarness{t: t, binary: binary, dir: dir, env: map[string]string{
		"XDG_DATA_HOME": filepath.Join(dir, "data"), "ENBU_IDENTITY_BACKEND": backend, "ENBU_TEST_TPM_URL": "",
		"GITHUB_TOKEN": "fixture-token", "GITHUB_ACTOR": "e2e-user", "NO_COLOR": "1",
	}}
}

func buildCLI(t *testing.T, host string, testTransport bool) string {
	t.Helper()
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"type":"User"}`))
	}))
	t.Cleanup(api.Close)
	name := "enbu"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	binary := filepath.Join(t.TempDir(), name)
	args := []string{"build", "-buildvcs=false", "-ldflags", "-X main.Version=identity-e2e -X main.registryHost=" + host + " -X github.com/enbu-net/enbu/pkg/provider/github.apiBaseURL=" + api.URL + "/", "-o", binary}
	if testTransport {
		args = append(args, "-tags=identitytest")
	}
	args = append(args, ".")
	cmd := exec.Command("go", args...)
	cmd.Dir = filepath.Join("..", "..")
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build CLI: %s %v", out, err)
	}
	return binary
}

func TestIdentityCLI(t *testing.T) {
	registry := httptest.NewServer(newRegistry())
	defer registry.Close()
	host := "localhost:" + strings.Split(registry.Listener.Addr().String(), ":")[1]
	binary := buildCLI(t, host, true)
	t.Run("TPMLifecycleRestartMixedAndCorruption", func(t *testing.T) {
		h := newHarness(t, binary, "hardware")
		state := filepath.Join(t.TempDir(), "vtpm.json")
		endpoint, stop := startVTPM(t, state)
		h.env["ENBU_TEST_TPM_URL"] = endpoint
		created := h.run("identity", "create")
		if created["backend"] != "tpm" || created["algorithm"] != "P-256" {
			t.Fatalf("%+v", created)
		}
		recipient := created["recipient"].(string)
		if !strings.HasPrefix(recipient, "age1tag1") {
			t.Fatal(recipient)
		}
		if d := h.run("doctor"); d["available"] != true {
			t.Fatalf("doctor: %+v", d)
		}
		if result := h.run("init"); result["public_key"] != recipient {
			t.Fatalf("init changed key: %+v", result)
		}
		h.run("add", "DATABASE_URL", "first")
		assertSecret(t, h.run("pull"), "first")
		h.run("edit", "DATABASE_URL", "second")
		// Add a real X25519 recipient through the production OCI client.
		x, err := agecrypto.GenerateX25519Identity()
		if err != nil {
			t.Fatal(err)
		}
		ref := host + "/e2e/identity-enbu"
		if err := oci.Push(context.Background(), ref+":recipient-software-"+age.Fingerprint(x.Recipient().String()), "application/vnd.enbu.recipient.age.v1", []byte(x.Recipient().String()), "fixture-token", nil); err != nil {
			t.Fatal(err)
		}
		h.run("sync")
		ciphertext, err := oci.Pull(context.Background(), ref+":secrets-default", "fixture-token")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := age.Decrypt(ciphertext, x); err != nil {
			t.Fatalf("sync did not include X25519 recipient: %v", err)
		}
		stop()
		endpoint, _ = startVTPM(t, state)
		h.env["ENBU_TEST_TPM_URL"] = endpoint
		if shown := h.run("identity", "show"); shown["recipient"] != recipient {
			t.Fatal("recipient changed after restart")
		}
		assertSecret(t, h.run("pull"), "second")
		h.run("history", "diff", "1", "2")
		h.run("history", "restore", "1")
		assertSecret(t, h.run("pull"), "first")
		// Missing TPM and corrupt blobs must not replace a saved identity.
		m := &identity.Manager{Dir: filepath.Join(h.env["XDG_DATA_HOME"], "enbu", "identities")}
		path := m.Path("e2e", "identity")
		saved, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		h.env["ENBU_TEST_TPM_URL"] = "http://127.0.0.1:1"
		h.env["ENBU_IDENTITY_BACKEND"] = "auto"
		h.fails("identity", "create")
		if after, _ := os.ReadFile(path); !bytes.Equal(saved, after) {
			t.Fatal("replaced saved identity without hardware")
		}
		h.env["ENBU_TEST_TPM_URL"] = endpoint
		var md identity.Metadata
		if err := json.Unmarshal(saved, &md); err != nil {
			t.Fatal(err)
		}
		md.TPMPrivate[len(md.TPMPrivate)-1] ^= 1
		b, _ := json.Marshal(md)
		if err := os.WriteFile(path, b, 0o600); err != nil {
			t.Fatal(err)
		}
		h.fails("pull")
		h.fails("identity", "create")
		if after, _ := os.ReadFile(path); !bytes.Equal(b, after) {
			t.Fatal("replaced corrupt identity")
		}
	})
	t.Run("OSKeyringFallbackAndReload", func(t *testing.T) {
		h := newHarness(t, binary, "auto")
		cmd := exec.Command("git", "remote", "set-url", "origin", "https://github.com/e2e/fallback.git")
		cmd.Dir = h.dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git: %s %v", out, err)
		}
		h.env["ENBU_TEST_TPM_URL"] = "http://127.0.0.1:1"
		created := h.run("identity", "create") // Mandatory real keyring, no mocks.
		if created["backend"] != "keyring" || created["algorithm"] != "X25519" {
			t.Fatalf("fallback: %+v", created)
		}
		recipient := created["recipient"].(string)
		if shown := h.run("identity", "show"); shown["recipient"] != recipient {
			t.Fatal("keyring reload changed recipient")
		}
		if again := h.run("identity", "create"); again["recipient"] != recipient {
			t.Fatal("keyring creation did not reuse")
		}
		m := &identity.Manager{Dir: filepath.Join(h.env["XDG_DATA_HOME"], "enbu", "identities")}
		b, err := os.ReadFile(m.Path("e2e", "fallback"))
		if err != nil {
			t.Fatal(err)
		}
		var md identity.Metadata
		if err := json.Unmarshal(b, &md); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = keyring.Delete("enbu-identity-v1", md.Reference) })
		h.run("init")
		h.run("add", "DATABASE_URL", "first")
		h.run("sync")
		assertSecret(t, h.run("pull"), "first")
		h.env["ENBU_IDENTITY_BACKEND"] = "hardware"
		h.fails("identity", "show")
		h.env["ENBU_IDENTITY_BACKEND"] = "keyring"
		if err := keyring.Set("enbu-identity-v1", md.Reference, "corrupt"); err != nil {
			t.Fatal(err)
		}
		h.fails("pull")
		h.fails("identity", "create")
	})
	t.Run("ProductionBuildExcludesSoftwareTransport", func(t *testing.T) {
		production := buildCLI(t, host, false)
		h := newHarness(t, production, "hardware")
		endpoint, _ := startVTPM(t, filepath.Join(t.TempDir(), "state.json"))
		h.env["ENBU_TEST_TPM_URL"] = endpoint
		d := h.run("doctor")
		if d["device"] == "test-only vTPM" {
			t.Fatal("production build contains test transport")
		}
	})
}

func assertSecret(t *testing.T, data map[string]any, want string) {
	t.Helper()
	secrets, ok := data["secrets"].(map[string]any)
	if !ok || secrets["DATABASE_URL"] != want {
		t.Fatalf("pull: %+v, want DATABASE_URL=%s", data, want)
	}
}
