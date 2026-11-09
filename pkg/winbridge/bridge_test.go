package winbridge

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"filippo.io/age"
	enbuage "github.com/enbu-net/enbu/pkg/age"
	"github.com/enbu-net/enbu/pkg/apperr"
	"github.com/enbu-net/enbu/pkg/identity"
	"github.com/enbu-net/enbu/pkg/keystore"
	"github.com/enbu-net/enbu/pkg/signing"
)

const serveEnv = "ENBU_WINBRIDGE_TEST_SERVE"

// TestMain lets the test binary play enbu.exe: started with serveEnv, it
// serves the bridge on stdin and stdout, so the exec path is tested too.
func TestMain(m *testing.M) {
	if dir := os.Getenv(serveEnv); dir != "" {
		s := newServer(dir, &memVault{})
		if err := s.Serve(context.Background(), os.Stdin, os.Stdout); err != nil {
			os.Exit(1)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

type memVault struct {
	mu sync.Mutex
	m  map[string][]byte
}

func (v *memVault) Store(service, key string, value []byte) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.m == nil {
		v.m = map[string][]byte{}
	}
	v.m[service+"/"+key] = append([]byte(nil), value...)
	return nil
}

func (v *memVault) Load(service, key string) ([]byte, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	b, ok := v.m[service+"/"+key]
	if !ok {
		return nil, fs.ErrNotExist
	}
	return append([]byte(nil), b...), nil
}

func (v *memVault) Delete(service, key string) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if _, ok := v.m[service+"/"+key]; !ok {
		return fs.ErrNotExist
	}
	delete(v.m, service+"/"+key)
	return nil
}

func newServer(dir string, keyring keystore.Backend) *Server {
	return &Server{
		Version:    "v1.2.3",
		Identities: &identity.Manager{Dir: dir, Mode: "keyring", Vault: &memVault{}},
		Keyring:    keyring,
		Entries:    []KeyringEntry{{Service: "enbu", Key: "github-oauth"}},
	}
}

// pipeClient connects a client to s in this process.
func pipeClient(t *testing.T, s *Server) *Client {
	t.Helper()
	c := &Client{Dial: func() (*Conn, error) {
		reqR, reqW := io.Pipe()
		respR, respW := io.Pipe()
		done := make(chan error, 1)
		go func() {
			err := s.Serve(context.Background(), reqR, respW)
			_ = respW.Close()
			done <- err
		}()
		return &Conn{R: respR, W: reqW, Close: func() error {
			_ = reqW.Close()
			return <-done
		}}, nil
	}}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func TestIdentityRoundTrip(t *testing.T) {
	c := pipeClient(t, newServer(t.TempDir(), &memVault{}))

	id, info, _, err := c.Create("ws")
	if err != nil {
		t.Fatal(err)
	}
	if !info.Created || info.Backend != "keyring" || info.Recipient != id.Recipient().String() {
		t.Fatalf("info = %+v, recipient %s", info, id.Recipient())
	}
	ct, err := enbuage.EncryptForPublicKeys([]byte("secret"), []string{info.Recipient})
	if err != nil {
		t.Fatal(err)
	}
	pt, err := enbuage.Decrypt(ct, id)
	if err != nil || string(pt) != "secret" {
		t.Fatalf("decrypt = %q, %v", pt, err)
	}
	if err := id.Close(); err != nil {
		t.Fatal(err)
	}

	again, _, _, err := c.Create("ws")
	if err != nil {
		t.Fatal(err)
	}
	if again.Recipient().String() != info.Recipient {
		t.Fatal("Create made a second identity for the same workspace")
	}
	loaded, err := c.Load("ws")
	if err != nil {
		t.Fatal(err)
	}
	if pt, err := enbuage.Decrypt(ct, loaded); err != nil || string(pt) != "secret" {
		t.Fatalf("decrypt with loaded = %q, %v", pt, err)
	}
	shown, err := c.Info("ws")
	if err != nil || shown.Recipient != info.Recipient || shown.Created {
		t.Fatalf("Info = %+v, %v", shown, err)
	}
}

func TestAnotherRecipientIsNotAnError(t *testing.T) {
	c := pipeClient(t, newServer(t.TempDir(), &memVault{}))
	id, _, _, err := c.Create("ws")
	if err != nil {
		t.Fatal(err)
	}
	other, err := age.GenerateHybridIdentity()
	if err != nil {
		t.Fatal(err)
	}
	ct, err := enbuage.EncryptForPublicKeys([]byte("x"), []string{other.Recipient().String()})
	if err != nil {
		t.Fatal(err)
	}
	_, err = enbuage.Decrypt(ct, id)
	var noMatch *age.NoIdentityMatchError
	if !errors.As(err, &noMatch) {
		t.Fatalf("err = %v, want NoIdentityMatchError", err)
	}
	// The stream is still usable after a stanza that is not ours.
	if _, err := c.Info("ws"); err != nil {
		t.Fatal(err)
	}
}

func TestSignerRoundTrip(t *testing.T) {
	c := pipeClient(t, newServer(t.TempDir(), &memVault{}))
	s, info, _, err := c.CreateSigner("ws")
	if err != nil {
		t.Fatal(err)
	}
	if !info.Created || info.DeviceID == "" {
		t.Fatalf("info = %+v", info)
	}
	sig, err := s.Sign(signing.DomainState, []byte("body"))
	if err != nil {
		t.Fatal(err)
	}
	if err := signing.Verify(s.Public(), signing.DomainState, []byte("body"), sig); err != nil {
		t.Fatal(err)
	}
	loaded, err := c.LoadSigner("ws")
	if err != nil {
		t.Fatal(err)
	}
	if string(loaded.Public().Bytes) != string(s.Public().Bytes) {
		t.Fatal("LoadSigner returned another key")
	}
	shown, err := c.SignerInfo("ws")
	if err != nil || shown.DeviceID != info.DeviceID {
		t.Fatalf("SignerInfo = %+v, %v", shown, err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Sign(signing.DomainState, []byte("body")); err == nil {
		t.Fatal("a closed signer still signs")
	}
}

func TestKeyUpdateOverTheBridge(t *testing.T) {
	c := pipeClient(t, newServer(t.TempDir(), &memVault{}))
	old, _, _, err := c.Create("ws")
	if err != nil {
		t.Fatal(err)
	}
	_, pending, _, err := c.CreatePending("ws")
	if err != nil {
		t.Fatal(err)
	}
	if got, err := c.PendingInfo("ws"); err != nil || got.Recipient != pending.Recipient {
		t.Fatalf("PendingInfo = %+v, %v", got, err)
	}
	retained, err := c.LoadRetained("ws")
	if err != nil || len(retained) != 1 || retained[0].Recipient().String() != pending.Recipient {
		t.Fatalf("LoadRetained = %v, %v", retained, err)
	}
	if err := c.PromotePending("ws"); err != nil {
		t.Fatal(err)
	}
	if info, err := c.Info("ws"); err != nil || info.Recipient != pending.Recipient || info.Recipient == old.Recipient().String() {
		t.Fatalf("Info after promote = %+v, %v", info, err)
	}
}

func TestMissingIdentityIsNotExist(t *testing.T) {
	c := pipeClient(t, newServer(t.TempDir(), &memVault{}))
	if _, err := c.Load("nope"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("Load = %v, want fs.ErrNotExist", err)
	}
	if _, err := c.SignerInfo("nope"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("SignerInfo = %v, want fs.ErrNotExist", err)
	}
}

func TestKeyringSharesOnlyItsEntries(t *testing.T) {
	c := pipeClient(t, newServer(t.TempDir(), &memVault{}))
	k := c.Keyring()
	if _, err := k.Load("enbu", "github-oauth"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("Load before Store = %v, want fs.ErrNotExist", err)
	}
	if err := k.Store("enbu", "github-oauth", []byte("token")); err != nil {
		t.Fatal(err)
	}
	if b, err := k.Load("enbu", "github-oauth"); err != nil || string(b) != "token" {
		t.Fatalf("Load = %q, %v", b, err)
	}
	if err := k.Delete("enbu", "github-oauth"); err != nil {
		t.Fatal(err)
	}
	if _, err := k.Load("enbu-identity", "anything"); err == nil || !strings.Contains(err.Error(), errKeyringEntryForbidden) {
		t.Fatalf("Load of an identity key = %v, want refused", err)
	}
}

func TestDoctorNamesTheWindowsSide(t *testing.T) {
	c := pipeClient(t, newServer(t.TempDir(), &memVault{}))
	d := c.Doctor(context.Background())
	if d.WSL == nil || d.WSL.Version != "v1.2.3" || d.WSL.Error != "" {
		t.Fatalf("WSL = %+v", d.WSL)
	}
	if d.Mode != "keyring" || !d.FallbackAvailable {
		t.Fatalf("diagnosis = %+v, want the server's", d)
	}
}

func TestNoBridgeIsUnavailable(t *testing.T) {
	c := &Client{Dial: func() (*Conn, error) { return nil, errors.New("the Windows enbu.exe was not found on PATH") }}
	_, err := c.Load("ws")
	var unavailable *identity.UnavailableError
	if !errors.As(err, &unavailable) || !strings.Contains(unavailable.Reason, "not found on PATH") {
		t.Fatalf("Load = %v, want unavailable with the reason", err)
	}
	if _, err := c.Keyring().Load("enbu", "github-oauth"); !errors.Is(err, keystore.ErrNoKeyring) {
		t.Fatalf("token Load = %v, want ErrNoKeyring", err)
	}
	d := c.Doctor(context.Background())
	if d.WSL == nil || !strings.Contains(d.WSL.Error, "not found on PATH") || d.Available {
		t.Fatalf("Doctor = %+v", d)
	}
}

func TestOtherProtocolIsRefused(t *testing.T) {
	s := newServer(t.TempDir(), &memVault{})
	in := strings.NewReader(`{"id":1,"method":"identity.load","params":{"workspace_id":"ws"}}` + "\n" +
		`{"id":2,"method":"hello","params":{"protocol":99}}` + "\n")
	var out strings.Builder
	if err := s.Serve(context.Background(), in, &out); err != nil {
		t.Fatal(err)
	}
	dec := json.NewDecoder(strings.NewReader(out.String()))
	for _, want := range []string{"hello first", errIncompatibleProtocol} {
		var resp response
		if err := dec.Decode(&resp); err != nil {
			t.Fatal(err)
		}
		if resp.Error == nil || !strings.Contains(resp.Error.Message, want) {
			t.Fatalf("response = %+v, want an error with %q", resp, want)
		}
	}
}

func TestErrorsKeepTheirKind(t *testing.T) {
	locked := &identity.UnavailableError{Reason: "unlock it", Err: keystore.ErrLocked}
	err := encodeError(locked).decode()
	var unavailable *identity.UnavailableError
	if !errors.As(err, &unavailable) || unavailable.Reason != "unlock it" || !errors.Is(err, keystore.ErrLocked) {
		t.Fatalf("decoded %v", err)
	}
	coded := encodeError(apperr.New(apperr.CodeKeyringLocked, "locked", nil)).decode()
	if !apperr.Is(coded, apperr.CodeKeyringLocked) {
		t.Fatalf("decoded %v, want keyring_locked", coded)
	}
}

func TestTheProcessBridge(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv(serveEnv, t.TempDir())
	c := &Client{Dial: func() (*Conn, error) { return Exec(exe) }}
	t.Cleanup(func() { _ = c.Close() })
	id, info, _, err := c.Create("ws")
	if err != nil {
		t.Fatal(err)
	}
	ct, err := enbuage.EncryptForPublicKeys([]byte("over a pipe"), []string{info.Recipient})
	if err != nil {
		t.Fatal(err)
	}
	if pt, err := enbuage.Decrypt(ct, id); err != nil || string(pt) != "over a pipe" {
		t.Fatalf("decrypt = %q, %v", pt, err)
	}
}

func TestDetect(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	plain := write("linux", "Linux version 6.8.0-45-generic (buildd@lcy02)")
	wsl2 := write("wsl2", "Linux version 5.15.153.1-microsoft-standard-WSL2")
	wsl1 := write("wsl1", "Linux version 4.4.0-19041-Microsoft (Microsoft@Microsoft.com)")
	interop := []string{write("WSLInterop", "enabled")}
	noInterop := []string{filepath.Join(dir, "missing")}
	none := func(string) string { return "" }
	withInterop := func(k string) string {
		if k == "WSL_INTEROP" {
			return "/run/WSL/1_interop"
		}
		return ""
	}
	linux := runtime.GOOS == "linux"
	for _, tc := range []struct {
		name    string
		getenv  func(string) string
		file    string
		interop []string
		want    bool
	}{
		{"plain Linux", none, plain, interop, false},
		{"WSL 2 with interop", none, wsl2, interop, linux},
		{"WSL 1", none, wsl1, noInterop, linux},
		{"WSL_INTEROP", withInterop, plain, noInterop, linux},
		// Docker Desktop and devcontainers share the WSL 2 kernel but have no
		// interop: they keep their own keystore.
		{"container on a WSL 2 kernel", none, wsl2, noInterop, false},
	} {
		if got := detect(tc.getenv, tc.file, tc.interop); got != tc.want {
			t.Errorf("%s: detect = %t, want %t", tc.name, got, tc.want)
		}
	}
}

func TestLocate(t *testing.T) {
	t.Setenv(ExeEnv, "/mnt/c/tools/enbu.exe")
	if p, err := Locate(); err != nil || p != "/mnt/c/tools/enbu.exe" {
		t.Fatalf("Locate = %q, %v, want the %s path", p, err, ExeEnv)
	}
	t.Setenv(ExeEnv, "")
	t.Setenv("PATH", t.TempDir())
	if _, err := Locate(); err == nil || !strings.Contains(err.Error(), "not found on PATH") || !strings.Contains(err.Error(), ExeEnv) {
		t.Fatalf("Locate = %v, want a not-found message naming %s", err, ExeEnv)
	}
}

func TestRunWindowsPassesTheTerminal(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses a shell script as enbu.exe")
	}
	script := filepath.Join(t.TempDir(), "enbu.exe")
	if err := os.WriteFile(script, []byte("#!/bin/sh\nread line\necho \"$* $line\"\necho oops >&2\nexit 3\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv(ExeEnv, script)
	var out, errOut strings.Builder
	err := RunWindows(context.Background(), strings.NewReader("typed\n"), &out, &errOut, "auth", "login")
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 3 {
		t.Fatalf("RunWindows = %v, want exit status 3", err)
	}
	if out.String() != "auth login typed\n" || errOut.String() != "oops\n" {
		t.Fatalf("stdout %q, stderr %q", out.String(), errOut.String())
	}
	t.Setenv(ExeEnv, filepath.Join(t.TempDir(), "missing.exe"))
	if err := RunWindows(context.Background(), nil, io.Discard, io.Discard); err == nil || !strings.Contains(err.Error(), "interop") {
		t.Fatalf("RunWindows = %v, want a start failure naming interop", err)
	}
}

func TestCloseKillsAStuckExe(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses sleep")
	}
	cmd := exec.Command("sleep", "60")
	if err := cmd.Start(); err != nil {
		t.Skip("no sleep: ", err)
	}
	if err := waitOrKill(cmd, 10*time.Millisecond); err == nil {
		t.Fatal("a stuck process exited cleanly")
	}
}

func TestAnExeThatCannotStartNamesInterop(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "enbu.exe")
	c := &Client{Dial: func() (*Conn, error) { return Exec(missing) }}
	_, err := c.Info("ws")
	if !errors.Is(err, identity.ErrUnavailable) || !strings.Contains(err.Error(), "interop") || !strings.Contains(err.Error(), missing) {
		t.Fatalf("Info = %v, want unavailable naming the path and interop", err)
	}
}

func TestAnOlderExeIsNamed(t *testing.T) {
	// An enbu.exe without the bridge prints its usage error and exits.
	c := &Client{Dial: func() (*Conn, error) {
		return &Conn{R: strings.NewReader(""), W: nopWriteCloser{io.Discard}, Close: func() error { return nil }}, nil
	}}
	_, err := c.Info("ws")
	if !errors.Is(err, identity.ErrUnavailable) || !strings.Contains(err.Error(), "same version") {
		t.Fatalf("Info = %v, want a version hint", err)
	}
}

type nopWriteCloser struct{ io.Writer }

func (nopWriteCloser) Close() error { return nil }
