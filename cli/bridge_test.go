package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"strings"
	"testing"

	"github.com/enbu-net/enbu/app"
	"github.com/enbu-net/enbu/pkg/auth"
	"github.com/enbu-net/enbu/pkg/identity"
	"github.com/spf13/cobra"
)

// The hidden bridge command answers the WSL side on stdout and nothing else:
// any other output would break the stream.
func TestIdentityBridgeServesOnStdio(t *testing.T) {
	a := &app.App{Identities: &identity.Manager{Dir: t.TempDir(), Mode: "keyring", Vault: identityMemVault{}}}
	cmd := NewWithApp("v9.9.9", a)
	var out, errOut bytes.Buffer
	cmd.SetIn(strings.NewReader(`{"id":1,"method":"hello","params":{"protocol":1}}` + "\n" +
		`{"id":2,"method":"identity.create","params":{"workspace_id":"ws"}}` + "\n"))
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
	cmd := NewWithApp("test", &app.App{Identities: &staticKeyStore{}})
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
		{[]string{"--device"}, "auth login --device"},
	} {
		var got []string
		deps := authLoginDeps{
			browserLogin: func(context.Context, auth.BrowserOpener) (*auth.StoredToken, error) {
				return nil, errors.New("logged in inside WSL")
			},
			deviceLogin: func(context.Context, string, auth.DevicePrompter) (*auth.StoredToken, error) {
				return nil, errors.New("logged in inside WSL")
			},
			windows: func(_ context.Context, _ *cobra.Command, args ...string) error {
				got = args
				return nil
			},
		}
		cmd := newAuthLoginCommandWithDeps(deps)
		cmd.SetOut(&bytes.Buffer{})
		cmd.SetArgs(tc.args)
		if err := cmd.ExecuteContext(context.Background()); err != nil {
			t.Fatal(err)
		}
		if strings.Join(got, " ") != tc.want {
			t.Fatalf("ran %q, want %q", got, tc.want)
		}
	}
}

type wslDoctorKeyStore struct {
	staticKeyStore
	status identity.WSLStatus
}

func (s *wslDoctorKeyStore) Doctor(context.Context) identity.Diagnosis {
	d := identity.Diagnosis{Mode: "auto", Backend: "tpm", Available: s.status.Error == "", WSL: &s.status}
	if s.status.Error != "" {
		d.Backend, d.Reason = "windows", s.status.Error
	}
	return d
}

func TestDoctorShowsTheWindowsEnbuInsideWSL(t *testing.T) {
	for _, tc := range []struct {
		status identity.WSLStatus
		want   []string
	}{
		{identity.WSLStatus{Exe: "/mnt/c/enbu/enbu.exe", Version: "v1.0.0"},
			[]string{"Windows enbu: /mnt/c/enbu/enbu.exe (v1.0.0)", "identity_backend: ok — New identities use the hardware (tpm) of Windows"}},
		{identity.WSLStatus{Error: "the Windows enbu.exe was not found on PATH"},
			[]string{"Windows enbu error: the Windows enbu.exe was not found on PATH", "identity_backend: warn", "(identity_unavailable)"}},
	} {
		a := &app.App{Identities: &wslDoctorKeyStore{status: tc.status}, RepositoryDir: t.TempDir()}
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
