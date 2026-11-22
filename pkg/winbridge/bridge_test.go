package winbridge

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
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
	"github.com/jonboulle/clockwork"
)

const serveEnv = "ENBU_WINBRIDGE_TEST_SERVE"

// TestMain lets the test binary play enbu.exe: started with serveEnv, it
// serves the bridge on stdin and stdout, so the exec path is tested too.
func TestMain(m *testing.M) {
	if dir := os.Getenv(serveEnv); dir != "" {
		s := newServer(dir)
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

func (v *memVault) Probe(context.Context) error { return nil }

func (v *memVault) Delete(service, key string) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if _, ok := v.m[service+"/"+key]; !ok {
		return fs.ErrNotExist
	}
	delete(v.m, service+"/"+key)
	return nil
}

func newServer(dir string) *Server {
	return &Server{
		Version:    "v1.2.3",
		Identities: &identity.Manager{Dir: dir, Mode: "keyring", Vault: &memVault{}},
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

type observedDoneContext struct {
	context.Context
	observed chan struct{}
	once     sync.Once
}

func (c *observedDoneContext) Done() <-chan struct{} {
	c.once.Do(func() { close(c.observed) })
	return c.Context.Done()
}

func TestCheckProtocolCancelsHandshakeAndReconnects(t *testing.T) {
	c := pipeClient(t, newServer(t.TempDir()))
	dial := c.Dial
	reqR, reqW := io.Pipe()
	respR, respW := io.Pipe()
	t.Cleanup(func() {
		_ = reqR.Close()
		_ = respW.Close()
		_ = reqW.Close()
		_ = respR.Close()
	})
	dials := 0
	c.Dial = func() (*Conn, error) {
		dials++
		if dials > 1 {
			return dial()
		}
		return &Conn{R: respR, W: reqW, Close: func() error {
			_ = reqW.Close()
			return respR.Close()
		}}, nil
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	result := make(chan error, 1)
	go func() { result <- c.CheckProtocol(ctx) }()

	// Read the client's request but leave stdout open without a response.
	var req request
	if err := json.NewDecoder(reqR).Decode(&req); err != nil || req.Method != methodHello {
		t.Fatalf("reading hello: got %q, %v", req.Method, err)
	}
	waiting, cancelWaiting := context.WithCancel(t.Context())
	defer cancelWaiting()
	observed := &observedDoneContext{Context: waiting, observed: make(chan struct{})}
	waitingResult := make(chan error, 1)
	go func() { waitingResult <- c.CheckProtocol(observed) }()
	// The stalled hello owns the lock. Done is consulted by the second
	// caller while attempting to acquire it, with its context still live.
	select {
	case <-observed.observed:
	case err := <-waitingResult:
		t.Fatalf("queued preflight returned before cancellation: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("queued preflight did not start waiting")
	}
	cancelWaiting()
	select {
	case err := <-waitingResult:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("queued preflight = %v, want context.Canceled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("queued preflight did not cancel")
	}

	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("stalled preflight = %v, want context.Canceled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("stalled preflight did not cancel")
	}

	retry, stopRetry := context.WithTimeout(t.Context(), 5*time.Second)
	defer stopRetry()
	for range 2 {
		if err := c.CheckProtocol(retry); err != nil {
			t.Fatal(err)
		}
	}
	if dials != 2 {
		t.Fatalf("dialed %d times, want one cancelled and one reused connection", dials)
	}
}

func TestStalledDoctorCanBeCancelledAndClosed(t *testing.T) {
	for _, shutdown := range []string{"context", "close", "timeout"} {
		t.Run(shutdown, func(t *testing.T) {
			reqR, reqW := io.Pipe()
			respR, respW := io.Pipe()
			t.Cleanup(func() {
				_ = reqR.Close()
				_ = respW.Close()
			})
			clock := clockwork.NewFakeClock()
			c := &Client{Clock: clock, Dial: func() (*Conn, error) {
				return &Conn{R: respR, W: reqW}, nil
			}}
			requested := make(chan error, 1)
			go func() {
				dec := json.NewDecoder(reqR)
				var req request
				if err := dec.Decode(&req); err != nil {
					requested <- err
					return
				}
				result, err := json.Marshal(helloResult{Protocol: Protocol, Version: "test"})
				if err == nil {
					err = json.NewEncoder(respW).Encode(response{ID: req.ID, Result: result})
				}
				if err == nil {
					err = dec.Decode(&req)
				}
				if err == nil && req.Method != methodDoctor {
					err = fmt.Errorf("unexpected method %q", req.Method)
				}
				requested <- err
			}()
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			done := make(chan identity.Diagnosis, 1)
			go func() { done <- c.Doctor(ctx) }()
			select {
			case err := <-requested:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("doctor did not send a request")
			}
			closed := make(chan struct{})
			want := context.Canceled
			if shutdown == "close" {
				go func() { _ = c.Close(); close(closed) }()
			} else {
				if shutdown == "timeout" {
					want = context.DeadlineExceeded
					clock.Advance(rpcTimeout)
				} else {
					cancel()
				}
				close(closed)
			}
			select {
			case diagnosis := <-done:
				if diagnosis.WSL == nil || !strings.Contains(diagnosis.WSL.Error, want.Error()) {
					t.Fatalf("diagnosis = %+v", diagnosis)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("doctor stayed blocked")
			}
			select {
			case <-closed:
			case <-time.After(5 * time.Second):
				t.Fatal("Close stayed blocked")
			}
		})
	}
}

func TestCheckProtocolClassifiesHandshakeTimeout(t *testing.T) {
	reqR, reqW := io.Pipe()
	respR, respW := io.Pipe()
	t.Cleanup(func() {
		_ = reqR.Close()
		_ = respW.Close()
	})
	clock := clockwork.NewFakeClock()
	c := &Client{Clock: clock, Dial: func() (*Conn, error) {
		return &Conn{R: respR, W: reqW}, nil
	}}
	t.Cleanup(func() { _ = c.Close() })
	done := make(chan error, 1)
	go func() { done <- c.CheckProtocol(t.Context()) }()
	var req request
	if err := json.NewDecoder(reqR).Decode(&req); err != nil {
		t.Fatal(err)
	}
	clock.Advance(rpcTimeout)
	select {
	case err := <-done:
		var unavailable *identity.UnavailableError
		if !errors.As(err, &unavailable) || !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("handshake timeout = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("handshake stayed blocked")
	}
}

func TestBeginRejectsClosingBridge(t *testing.T) {
	c := &Client{closing: true}
	if ctx, done, err := c.begin(t.Context()); err == nil || ctx != nil || done != nil {
		t.Fatal("closing bridge returned a usable operation")
	}
}

func TestRequestDeadlineStartsAfterAcquiringStream(t *testing.T) {
	fake := clockwork.NewFakeClock()
	c := &Client{Clock: fake}
	if err := c.mu.acquire(t.Context()); err != nil {
		t.Fatal(err)
	}
	parent := &observedDoneContext{Context: t.Context(), observed: make(chan struct{})}
	result := make(chan error, 1)
	go func() {
		ctx, done, err := c.begin(parent)
		if err == nil {
			err = ctx.Err()
			done()
		}
		result <- err
	}()
	select {
	case <-parent.observed:
	case <-time.After(5 * time.Second):
		t.Fatal("request did not queue")
	}
	fake.Advance(2 * rpcTimeout)
	c.mu.Unlock()
	if err := <-result; err != nil {
		t.Fatalf("queued request already expired: %v", err)
	}
}

// After enbu.exe restarts, a handle from the old process may name another key
// in the new one, so it is refused, and closing it sends nothing.
func TestAHandleBelongsToItsProcess(t *testing.T) {
	c := pipeClient(t, newServer(t.TempDir()))
	device, info, _, err := c.Create("a")
	if err != nil {
		t.Fatal(err)
	}
	old, signer := device.Identity, device.Signer
	if err := c.Close(); err != nil { // the stream ends, as when enbu.exe dies
		t.Fatal(err)
	}
	if _, _, _, err := c.Create("b"); err != nil {
		t.Fatal(err)
	}
	ct, err := enbuage.EncryptForPublicKeys([]byte("secret"), []string{info.Recipient})
	if err != nil {
		t.Fatal(err)
	}
	var unavailable *identity.UnavailableError
	if _, err := enbuage.Decrypt(ct, old); !errors.As(err, &unavailable) {
		t.Fatalf("decrypt with a handle of the old process = %v, want unavailable", err)
	}
	if _, err := signer.Sign("d", []byte("x")); !errors.As(err, &unavailable) {
		t.Fatalf("sign with a handle of the old process = %v, want unavailable", err)
	}
	if err := old.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestIdentityRoundTrip(t *testing.T) {
	c := pipeClient(t, newServer(t.TempDir()))

	device, info, _, err := c.Create("ws")
	if err != nil {
		t.Fatal(err)
	}
	id := device.Identity
	if !info.Created || info.Backend != "keyring" || info.Recipient != id.Recipient().String() || info.DeviceID != string(device.Signer.Public().DeviceID()) {
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
	if err := device.Close(); err != nil {
		t.Fatal(err)
	}

	again, _, _, err := c.Create("ws")
	if err != nil {
		t.Fatal(err)
	}
	if again.Identity.Recipient().String() != info.Recipient {
		t.Fatal("Create made a second identity for the same workspace")
	}
	loaded, err := c.Load("ws")
	if err != nil {
		t.Fatal(err)
	}
	if pt, err := enbuage.Decrypt(ct, loaded.Identity); err != nil || string(pt) != "secret" {
		t.Fatalf("decrypt with loaded = %q, %v", pt, err)
	}
	shown, err := c.Info("ws")
	if err != nil || shown.Recipient != info.Recipient || shown.Created {
		t.Fatalf("Info = %+v, %v", shown, err)
	}
}

func TestAnotherRecipientIsNotAnError(t *testing.T) {
	c := pipeClient(t, newServer(t.TempDir()))
	device, _, _, err := c.Create("ws")
	if err != nil {
		t.Fatal(err)
	}
	id := device.Identity
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
	c := pipeClient(t, newServer(t.TempDir()))
	device, _, _, err := c.Create("ws")
	if err != nil {
		t.Fatal(err)
	}
	s := device.Signer
	sig, err := s.Sign(signing.DomainState, []byte("body"))
	if err != nil {
		t.Fatal(err)
	}
	if err := signing.Verify(s.Public(), signing.DomainState, []byte("body"), sig); err != nil {
		t.Fatal(err)
	}
	loaded, err := c.Load("ws")
	if err != nil {
		t.Fatal(err)
	}
	if string(loaded.Signer.Public().Bytes) != string(s.Public().Bytes) {
		t.Fatal("Load returned another signing key")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Sign(signing.DomainState, []byte("body")); err == nil {
		t.Fatal("a closed signer still signs")
	}
}

func TestMissingIdentityIsNotExist(t *testing.T) {
	c := pipeClient(t, newServer(t.TempDir()))
	if _, err := c.Load("nope"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("Load = %v, want fs.ErrNotExist", err)
	}
	if _, err := c.Info("nope"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("Info = %v, want fs.ErrNotExist", err)
	}
}

func TestGitHubAuthDoesNotExposeOldKeyringRPC(t *testing.T) {
	c := pipeClient(t, newServer(t.TempDir()))
	for _, method := range []string{"keyring.load", "keyring.store", "keyring.delete"} {
		err := c.call(method, map[string]string{"service": "enbu", "key": "github-oauth"}, nil)
		if err == nil || !strings.Contains(err.Error(), errUnknownMethod) {
			t.Fatalf("%s = %v, want unknown method", method, err)
		}
	}
}

func TestDoctorNamesTheWindowsSide(t *testing.T) {
	c := pipeClient(t, newServer(t.TempDir()))
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
	if err := c.GitHubAuth("load", struct{}{}, nil); !errors.Is(err, identity.ErrUnavailable) {
		t.Fatalf("credential load = %v, want ErrUnavailable", err)
	}
	d := c.Doctor(context.Background())
	if d.WSL == nil || !strings.Contains(d.WSL.Error, "not found on PATH") || d.Available {
		t.Fatalf("Doctor = %+v", d)
	}
}

func TestOtherProtocolIsRefused(t *testing.T) {
	s := newServer(t.TempDir())
	in := strings.NewReader(`{"id":1,"method":"device.load","params":{"workspace_id":"ws"}}` + "\n" +
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
	device, info, _, err := c.Create("ws")
	if err != nil {
		t.Fatal(err)
	}
	ct, err := enbuage.EncryptForPublicKeys([]byte("over a pipe"), []string{info.Recipient})
	if err != nil {
		t.Fatal(err)
	}
	if pt, err := enbuage.Decrypt(ct, device.Identity); err != nil || string(pt) != "over a pipe" {
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
	oldWSL2 := write("oldwsl2", "Linux version 4.19.128-microsoft-standard (oe-user@oe-host)")
	wsl1 := write("wsl1", "Linux version 4.4.0-19041-Microsoft (Microsoft@Microsoft.com)")
	interop := []string{write("WSLInterop", "enabled")}
	noInterop := []string{filepath.Join(dir, "missing")}
	mounts := []string{filepath.Join(dir, "missing"), t.TempDir()} // /mnt/wsl with interop off
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
		{"container on an older WSL 2 kernel", none, oldWSL2, noInterop, false},
		{"older WSL 2 kernel", none, oldWSL2, interop, linux},
		// Interop off: still WSL, so enbu stops instead of using a Linux keystore.
		{"WSL 2 with interop off", none, wsl2, mounts, linux},
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

func TestCloseKillsAStuckExe(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses sleep")
	}
	cmd := exec.Command("sleep", "60")
	if err := cmd.Start(); err != nil {
		t.Skip("no sleep: ", err)
	}
	fake := clockwork.NewFakeClock()
	done := make(chan error, 1)
	go func() { done <- waitOrKill(cmd, fake, closeGrace) }()
	if err := fake.BlockUntilContext(context.Background(), 1); err != nil {
		t.Fatal(err)
	}
	fake.Advance(closeGrace)
	if err := <-done; err == nil {
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
		return &Conn{R: io.NopCloser(strings.NewReader("")), W: nopWriteCloser{io.Discard}, Close: func() error { return nil }}, nil
	}}
	_, err := c.Info("ws")
	if !errors.Is(err, identity.ErrUnavailable) || !strings.Contains(err.Error(), "same version") {
		t.Fatalf("Info = %v, want a version hint", err)
	}
}

type nopWriteCloser struct{ io.Writer }

func (nopWriteCloser) Close() error { return nil }
