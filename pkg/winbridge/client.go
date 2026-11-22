package winbridge

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sync"
	"time"

	"filippo.io/age"
	enbuage "github.com/enbu-net/enbu/pkg/age"
	"github.com/enbu-net/enbu/pkg/clock"
	"github.com/enbu-net/enbu/pkg/identity"
	"github.com/enbu-net/enbu/pkg/signing"
)

// Conn is one bridge stream: requests go to W, responses come from R. Close
// ends the Windows process.
type Conn struct {
	R     io.ReadCloser
	W     io.WriteCloser
	Close func() error
	abort func()
}

// Client is the WSL side. It implements the app's identity store by asking
// the Windows enbu.exe, which it starts on first use and keeps for the life
// of this process.
type Client struct {
	// Dial opens the stream. It defaults to starting enbu.exe from Locate.
	Dial func() (*Conn, error)

	mu      contextMutex
	conn    *Conn
	enc     *json.Encoder
	dec     *json.Decoder
	next    uint64
	gen     uint64 // counts connections; a handle is valid only on its own
	exe     string
	version string

	closeMu  sync.Mutex
	activeMu sync.Mutex
	cancel   context.CancelFunc
	closing  bool
}

// contextMutex lets a cancelled preflight leave the queue even if an
// earlier RPC is still waiting for Windows.
type contextMutex struct {
	once sync.Once
	slot chan struct{}
}

func (m *contextMutex) acquire(ctx context.Context) error {
	m.once.Do(func() { m.slot = make(chan struct{}, 1) })
	select {
	case m.slot <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (m *contextMutex) Unlock() { <-m.slot }

const rpcTimeout = time.Minute

// begin registers cancellation independently of the stream lock so Close can
// interrupt a request even while it is blocked in pipe I/O.
func (c *Client) begin(parent context.Context) (context.Context, func(), error) {
	ctx, cancel := context.WithTimeout(parent, rpcTimeout)
	if err := c.mu.acquire(ctx); err != nil {
		cancel()
		return nil, nil, err
	}
	c.activeMu.Lock()
	if c.closing || ctx.Err() != nil {
		c.activeMu.Unlock()
		cancel()
		c.mu.Unlock()
		return nil, nil, ctx.Err()
	}
	c.cancel = cancel
	c.activeMu.Unlock()
	return ctx, func() {
		c.activeMu.Lock()
		c.cancel = nil
		c.activeMu.Unlock()
		cancel()
		c.mu.Unlock()
	}, nil
}

var shared = sync.OnceValue(func() *Client { return &Client{} })

// Shared is the one client of this process, so the identity store and the
// token store share one enbu.exe.
func Shared() *Client { return shared() }

// Exec starts path as the bridge server.
func Exec(path string) (*Conn, error) {
	cmd := exec.Command(path, "identity", "bridge", "--stdio")
	cmd.Stderr = os.Stderr // TPM messages
	w, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	r, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("could not start the Windows %s (%s): %w; %s", exe, path, err, interopHint)
	}
	return &Conn{
		R: r, W: w,
		Close: func() error {
			_ = w.Close()
			return waitOrKill(cmd, clock.New(), closeGrace)
		},
		abort: func() { _ = cmd.Process.Kill() },
	}, nil
}

// closeGrace is how long enbu.exe gets to exit after its stdin closes. One
// stuck on a hung TPM call is killed after it, so
// the WSL command can always end.
var closeGrace = 5 * time.Second

func waitOrKill(cmd *exec.Cmd, c clock.Clock, grace time.Duration) error {
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	timer := c.NewTimer(grace)
	defer timer.Stop()
	select {
	case err := <-done:
		return err
	case <-timer.Chan():
		_ = cmd.Process.Kill()
		return <-done
	}
}

func (c *Client) dial() (*Conn, error) {
	if c.Dial != nil {
		return c.Dial()
	}
	path, err := Locate()
	if err != nil {
		return nil, err
	}
	c.exe = path
	return Exec(path)
}

// connect starts the bridge and agrees on the protocol. A failure is an
// unavailable identity backend: inside WSL there is no other place for keys.
func (c *Client) connect(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if c.conn != nil {
		return nil
	}
	conn, err := c.dial()
	if err != nil {
		return unavailable(err)
	}
	c.conn, c.enc, c.dec = conn, json.NewEncoder(conn.W), json.NewDecoder(conn.R)
	c.gen++
	var hello helloResult
	if err := c.roundTripContext(ctx, methodHello, helloParams{Protocol: Protocol}, &hello); err != nil {
		if ctx.Err() != nil {
			c.version = ""
			c.reset()
			return ctx.Err()
		}
		c.reset()
		var remote *remoteError
		if errors.As(err, &remote) {
			return unavailable(err)
		}
		return unavailable(fmt.Errorf("the Windows %s did not answer the bridge (is it an older enbu? install the same version in Windows and in WSL): %w", exe, err))
	}
	if hello.Protocol != Protocol {
		c.reset()
		return unavailable(fmt.Errorf("%s: Windows %s %s speaks %d, this enbu speaks %d; install the same enbu version in Windows and in WSL", errIncompatibleProtocol, exe, hello.Version, hello.Protocol, Protocol))
	}
	c.version = hello.Version
	return nil
}

func (c *Client) roundTripContext(ctx context.Context, method string, params, result any) error {
	conn := c.conn
	// Interrupt only this connection. The callback never takes the client
	// lock, which remains held until the protocol read returns.
	interrupted := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		_ = conn.R.Close()
		_ = conn.W.Close()
		if conn.abort != nil {
			conn.abort()
		}
		close(interrupted)
	})
	err := c.roundTrip(method, params, result)
	if !stop() {
		<-interrupted
		return ctx.Err()
	}
	return err
}

func unavailable(err error) error {
	return &identity.UnavailableError{Reason: "WSL keeps enbu's keys in Windows: " + err.Error(), Err: err}
}

// CheckProtocol verifies the version before starting sign-in.
func (c *Client) CheckProtocol(ctx context.Context) error {
	ctx, done, err := c.begin(ctx)
	if err != nil {
		return err
	}
	defer done()
	return c.connect(ctx)
}

func (c *Client) call(method string, params, result any) error {
	_, err := c.open(method, params, result)
	return err
}

// open is call for a request that opens handles: it also returns the
// connection they belong to.
func (c *Client) open(method string, params, result any) (uint64, error) {
	ctx, done, err := c.begin(context.Background())
	if err != nil {
		return 0, err
	}
	defer done()
	if err := c.connect(ctx); err != nil {
		return 0, err
	}
	return c.gen, c.send(ctx, method, params, result)
}

// callHandle uses a handle opened on connection gen. After enbu.exe restarted,
// the same number may name another key, so the call is refused instead.
func (c *Client) callHandle(gen uint64, method string, params, result any) error {
	ctx, done, err := c.begin(context.Background())
	if err != nil {
		return err
	}
	defer done()
	if c.conn == nil || c.gen != gen {
		return unavailable(fmt.Errorf("the Windows %s restarted, and the key this command opened is closed; run the command again", exe))
	}
	return c.send(ctx, method, params, result)
}

func (c *Client) send(ctx context.Context, method string, params, result any) error {
	err := c.roundTripContext(ctx, method, params, result)
	var remote *remoteError
	if err != nil && !errors.As(err, &remote) && !errors.Is(err, age.ErrIncorrectIdentity) {
		// The stream broke: start again on the next call.
		c.reset()
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return unavailable(fmt.Errorf("the Windows %s stopped answering: %w", exe, err))
	}
	return err
}

func (c *Client) roundTrip(method string, params, result any) error {
	c.next++
	raw, err := json.Marshal(params)
	if err != nil {
		return err
	}
	if err := c.enc.Encode(request{ID: c.next, Method: method, Params: raw}); err != nil {
		return err
	}
	var resp response
	if err := c.dec.Decode(&resp); err != nil {
		return err
	}
	if resp.ID != c.next {
		return fmt.Errorf("bridge answered request %d, expected %d", resp.ID, c.next)
	}
	if resp.Error != nil {
		return resp.Error.decode()
	}
	if result == nil {
		return nil
	}
	return json.Unmarshal(resp.Result, result)
}

func (c *Client) reset() {
	if c.conn != nil && c.conn.Close != nil {
		_ = c.conn.Close()
	}
	c.conn, c.enc, c.dec = nil, nil, nil
}

// Close ends the Windows process.
func (c *Client) Close() error {
	c.closeMu.Lock()
	defer c.closeMu.Unlock()
	c.activeMu.Lock()
	c.closing = true
	if c.cancel != nil {
		c.cancel()
	}
	c.activeMu.Unlock()
	_ = c.mu.acquire(context.Background())
	c.reset()
	c.activeMu.Lock()
	c.closing = false
	c.activeMu.Unlock()
	c.mu.Unlock()
	return nil
}

func ws(id string) workspaceParams { return workspaceParams{WorkspaceID: id} }

func (c *Client) Create(workspaceID string) (*identity.Device, identity.PublicInfo, string, error) {
	var r deviceResult
	gen, err := c.open(methodCreate, ws(workspaceID), &r)
	if err != nil {
		return nil, identity.PublicInfo{}, "", err
	}
	d, err := c.device(gen, r)
	if err != nil {
		return nil, identity.PublicInfo{}, "", err
	}
	r.Info.Created = r.Created
	return d, r.Info, r.Warning, nil
}

func (c *Client) Load(workspaceID string) (*identity.Device, error) {
	var r deviceResult
	gen, err := c.open(methodLoad, ws(workspaceID), &r)
	if err != nil {
		return nil, err
	}
	return c.device(gen, r)
}

func (c *Client) Info(workspaceID string) (identity.PublicInfo, error) {
	var r infoResult
	if err := c.call(methodInfo, ws(workspaceID), &r); err != nil {
		return identity.PublicInfo{}, err
	}
	r.Info.Created = r.Created
	return r.Info, nil
}

// Doctor reports the Windows side's diagnosis, and the bridge itself: a
// missing enbu.exe, disabled interop or another version is the problem to
// fix first.
func (c *Client) Doctor(ctx context.Context) identity.Diagnosis {
	var d identity.Diagnosis
	status := &identity.WSLStatus{}
	ctx, done, err := c.begin(ctx)
	if err == nil {
		defer done()
		err = c.connect(ctx)
		status.Exe, status.Version = c.exe, c.version
		if err == nil {
			err = c.send(ctx, methodDoctor, struct{}{}, &d)
		}
	}
	if err != nil {
		status.Error = err.Error()
		return identity.Diagnosis{Backend: "windows", Reason: status.Error, WSL: status}
	}
	d.WSL = status
	return d
}

func (c *Client) device(gen uint64, r deviceResult) (*identity.Device, error) {
	signer := &remoteSigner{c: c, gen: gen, handle: r.Signer, public: r.Public}
	parsed, err := enbuage.ParseRecipient(r.Recipient)
	recipient, ok := parsed.(identity.Recipient)
	if err != nil || !ok {
		_ = c.release(gen, r.Identity)
		_ = signer.Close()
		return nil, errors.New("the Windows enbu.exe returned an invalid recipient")
	}
	return &identity.Device{Identity: &remoteIdentity{c: c, gen: gen, handle: r.Identity, recipient: recipient}, Signer: signer}, nil
}

func (c *Client) release(gen, h uint64) error {
	ctx, done, err := c.begin(context.Background())
	if err != nil {
		return err
	}
	defer done()
	if c.conn == nil || c.gen != gen {
		return nil // the process is gone, and its handles with it
	}
	return c.send(ctx, methodClose, handleParams{Handle: h}, nil)
}

type remoteIdentity struct {
	c         *Client
	gen       uint64
	handle    uint64
	recipient identity.Recipient
}

func (r *remoteIdentity) Unwrap(stanzas []*age.Stanza) ([]byte, error) {
	var res unwrapResult
	if err := r.c.callHandle(r.gen, methodUnwrap, unwrapParams{Handle: r.handle, Stanzas: stanzas}, &res); err != nil {
		return nil, err
	}
	return res.FileKey, nil
}

func (r *remoteIdentity) Recipient() identity.Recipient { return r.recipient }
func (r *remoteIdentity) Close() error                  { return r.c.release(r.gen, r.handle) }

type remoteSigner struct {
	c      *Client
	gen    uint64
	handle uint64
	public signing.PublicKey
}

func (s *remoteSigner) Public() signing.PublicKey { return s.public }

func (s *remoteSigner) Sign(domain string, body []byte) ([]byte, error) {
	var res signResult
	if err := s.c.callHandle(s.gen, methodSign, signParams{Handle: s.handle, Domain: domain, Body: body}, &res); err != nil {
		return nil, err
	}
	return res.Signature, nil
}

func (s *remoteSigner) Close() error { return s.c.release(s.gen, s.handle) }

// GitHubAuth calls the Windows GitHub credential service.
func (c *Client) GitHubAuth(operation string, params, result any) error {
	raw, err := json.Marshal(params)
	if err != nil {
		return errors.New("invalid GitHub credential request")
	}
	return c.call(methodGitHubAuth, githubAuthParams{Operation: operation, Request: raw}, result)
}
