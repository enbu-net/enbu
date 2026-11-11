package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/enbu-net/enbu/app"
	"github.com/enbu-net/enbu/app/apptest"
	"github.com/enbu-net/enbu/pkg/apperr"
	"github.com/enbu-net/enbu/pkg/auth"
	"github.com/enbu-net/enbu/pkg/identity"
	"github.com/enbu-net/enbu/pkg/winbridge"
	"github.com/spf13/cobra"
)

// The hidden bridge command answers the WSL side on stdout and nothing else:
// any other output would break the stream.
func TestIdentityBridgeServesOnStdio(t *testing.T) {
	notInWSL(t)
	a := &app.App{Identities: &identity.Manager{Dir: t.TempDir(), Mode: "keyring", Vault: identityMemVault{}}}
	cmd := NewWithApp("v9.9.9", a)
	var out, errOut bytes.Buffer
	cmd.SetIn(strings.NewReader(`{"id":1,"method":"hello","params":{"protocol":2}}` + "\n" +
		`{"id":2,"method":"device.create","params":{"workspace_id":"ws"}}` + "\n"))
	cmd.SetOut(&out)
	cmd.SetErr(&errOut)
	cmd.SetArgs([]string{"identity", "bridge", "--stdio"})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err, errOut.String())
	}
	dec := json.NewDecoder(&out)
	var hello struct {
		Result struct {
			Version string `json:"version"`
		} `json:"result"`
	}
	if err := dec.Decode(&hello); err != nil || hello.Result.Version != "v9.9.9" {
		t.Fatalf("hello = %+v, %v", hello, err)
	}
	var created struct {
		Result struct {
			Recipient string `json:"recipient"`
		} `json:"result"`
		Error any `json:"error"`
	}
	if err := dec.Decode(&created); err != nil || created.Error != nil || !strings.HasPrefix(created.Result.Recipient, "age1") {
		t.Fatalf("create = %+v, %v", created, err)
	}
	if dec.More() {
		t.Fatal("the bridge wrote more than its responses")
	}
}

func TestIdentityBridgeNeedsStdio(t *testing.T) {
	cmd := NewWithApp("test", &app.App{Identities: &apptest.Identities{}})
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{"identity", "bridge"})
	if err := cmd.Execute(); err == nil {
		t.Fatal("bridge without --stdio ran")
	}
}

// Inside WSL, auth login runs in the Windows enbu.exe, with the same flags.
func TestAuthLoginRunsInWindowsInsideWSL(t *testing.T) {
	for _, tc := range []struct {
		args []string
		want string
	}{
		{nil, "auth login"},
		{[]string{"--json"}, "auth login --json"},
	} {
		var got []string
		deps := authLoginDeps{
			login: func(context.Context, auth.DevicePrompter) (*auth.StoredToken, error) {
				return nil, errors.New("logged in inside WSL")
			},
			windows: func(_ context.Context, _ *cobra.Command, args ...string) error {
				got = args
				return nil
			},
		}
		root := &cobra.Command{Use: "enbu"}
		root.PersistentFlags().Bool("json", false, "")
		root.AddCommand(newAuthLoginCommandWithDeps(deps))
		root.SetOut(&bytes.Buffer{})
		root.SetArgs(append([]string{"login"}, tc.args...))
		if err := root.ExecuteContext(context.Background()); err != nil {
			t.Fatal(err)
		}
		if strings.Join(got, " ") != tc.want {
			t.Fatalf("ran %q, want %q", got, tc.want)
		}
	}
}

type wslDoctorKeyStore struct {
	apptest.Identities
	status identity.WSLStatus
	noKeys bool // Windows has neither hardware nor Credential Manager
}

func (s *wslDoctorKeyStore) Doctor(context.Context) identity.Diagnosis {
	d := identity.Diagnosis{Mode: "auto", Backend: "tpm", Available: s.status.Error == "" && !s.noKeys, WSL: &s.status}
	if s.noKeys {
		d.KeyringReason = "Credential Manager is disabled"
	}
	if s.status.Error != "" {
		d.Backend, d.Reason = "windows", s.status.Error
	}
	return d
}

func TestDoctorShowsTheWindowsEnbuInsideWSL(t *testing.T) {
	for _, tc := range []struct {
		status identity.WSLStatus
		noKeys bool
		want   []string
	}{
		{identity.WSLStatus{Exe: "/mnt/c/enbu/enbu.exe", Version: "v1.0.0"}, false,
			[]string{"Windows enbu: /mnt/c/enbu/enbu.exe (v1.0.0)", "identity_backend: ok — New identities use the hardware (tpm) of Windows"}},
		{identity.WSLStatus{Error: "the Windows enbu.exe was not found on PATH"}, false,
			[]string{"Windows enbu: (not found)", "Windows enbu error: the Windows enbu.exe was not found on PATH", "identity_backend: warn", "(identity_unavailable)"}},
		// The Linux Secret Service would not help: WSL never uses it.
		{identity.WSLStatus{Exe: "/mnt/c/enbu/enbu.exe", Version: "v1.0.0"}, true,
			[]string{"Credential Manager is disabled. Run enbu.exe doctor in Windows.", "(identity_unavailable)"}},
	} {
		a := &app.App{Identities: &wslDoctorKeyStore{status: tc.status, noKeys: tc.noKeys}, RepositoryDir: t.TempDir()}
		cmd := NewWithApp("test", a)
		var out bytes.Buffer
		cmd.SetOut(&out)
		cmd.SetArgs([]string{"doctor"})
		if err := cmd.Execute(); err != nil {
			t.Fatal(err)
		}
		for _, w := range tc.want {
			if !strings.Contains(out.String(), w) {
				t.Fatalf("doctor output lacks %q:\n%s", w, out.String())
			}
		}
	}
}

// notInWSL makes the test behave the same on a WSL host.
func notInWSL(t *testing.T) {
	t.Helper()
	prev := inWSL
	inWSL = func() bool { return false }
	t.Cleanup(func() { inWSL = prev })
}

// An enbu.exe that cannot start is identity_unavailable and points to doctor.
func TestRunInWindowsNamesAMissingExe(t *testing.T) {
	t.Setenv(winbridge.ExeEnv, filepath.Join(t.TempDir(), "missing", "enbu.exe"))
	cmd := &cobra.Command{}
	cmd.SetOut(&bytes.Buffer{})
	err := runInWindows(context.Background(), cmd, "auth", "login")
	if apperr.CodeOf(err) != apperr.CodeIdentityUnavailable || !strings.Contains(err.Error(), "enbu doctor") {
		t.Fatalf("runInWindows = %v (%s), want identity_unavailable naming enbu doctor", err, apperr.CodeOf(err))
	}
}

type identityMemVault map[string][]byte

func (v identityMemVault) Store(_, key string, value []byte) error {
	v[key] = append([]byte(nil), value...)
	return nil
}

func (v identityMemVault) Load(_, key string) ([]byte, error) {
	b, ok := v[key]
	if !ok {
		return nil, fs.ErrNotExist
	}
	return append([]byte(nil), b...), nil
}

func (v identityMemVault) Delete(_, key string) error { delete(v, key); return nil }

func (identityMemVault) Probe(context.Context) error { return nil }

// A failed Windows login keeps its exit status and adds no second message.
func TestRunInWindowsKeepsTheExitStatus(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses a shell script as enbu.exe")
	}
	script := filepath.Join(t.TempDir(), "enbu.exe")
	if err := os.WriteFile(script, []byte("#!/bin/sh\nexit 4\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv(winbridge.ExeEnv, script)
	cmd := &cobra.Command{}
	cmd.SetOut(&bytes.Buffer{})
	err := runInWindows(context.Background(), cmd, "auth", "login")
	var exit *apperr.ExitError
	if !errors.As(err, &exit) || exit.Code != 4 {
		t.Fatalf("runInWindows = %v, want exit status 4", err)
	}
}
