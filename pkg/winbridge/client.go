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
	"github.com/enbu-net/enbu/pkg/identity"
	"github.com/enbu-net/enbu/pkg/keystore"
	"github.com/enbu-net/enbu/pkg/signing"
)

// Conn is one bridge stream: requests go to W, responses come from R. Close
// ends the Windows process.
type Conn struct {
	R     io.Reader
	W     io.WriteCloser
	Close func() error
}

// Client is the WSL side. It implements the app's identity store by asking
// the Windows enbu.exe, which it starts on first use and keeps for the life
// of this process.
type Client struct {
	// Dial opens the stream. It defaults to starting enbu.exe from Locate.
	Dial func() (*Conn, error)

	mu      sync.Mutex
	conn    *Conn
	enc     *json.Encoder
	dec     *json.Decoder
	next    uint64
	exe     string
	version string
}

var shared = sync.OnceValue(func() *Client { return &Client{} })

// Shared is the one client of this process, so the identity store and the
// token store share one enbu.exe.
func Shared() *Client { return shared() }

// Exec starts path as the bridge server.
func Exec(path string) (*Conn, error) {
	cmd := exec.Command(path, "identity", "bridge", "--stdio")
	cmd.Stderr = os.Stderr // Windows Hello and TPM messages
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
	return &Conn{R: r, W: w, Close: func() error {
		_ = w.Close()
		return waitOrKill(cmd, closeGrace)
	}}, nil
}

// closeGrace is how long enbu.exe gets to exit after its stdin closes. One
// stuck on a Windows Hello prompt or a hung TPM call is killed after it, so
// the WSL command can always end.
var closeGrace = 5 * time.Second

func waitOrKill(cmd *exec.Cmd, grace time.Duration) error {
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	timer := time.NewTimer(grace)
	defer timer.Stop()
	select {
	case err := <-done:
		return err
	case <-timer.C:
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
func (c *Client) connect() error {
	if c.conn != nil {
		return nil
	}
	conn, err := c.dial()
	if err != nil {
		return unavailable(err)
	}
	c.conn, c.enc, c.dec = conn, json.NewEncoder(conn.W), json.NewDecoder(conn.R)
	var hello helloResult
	if err := c.roundTrip(methodHello, helloParams{Protocol: Protocol}, &hello); err != nil {
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

func unavailable(err error) error {
	return &identity.UnavailableError{Reason: "WSL keeps enbu's keys in Windows: " + err.Error(), Err: err}
}

func (c *Client) call(method string, params, result any) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.connect(); err != nil {
		return err
	}
	err := c.roundTrip(method, params, result)
	var remote *remoteError
	if err != nil && !errors.As(err, &remote) && !errors.Is(err, age.ErrIncorrectIdentity) {
		// The stream broke: start again on the next call.
		c.reset()
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
	c.mu.Lock()
	defer c.mu.Unlock()
	c.reset()
	return nil
}

func (c *Client) status() *identity.WSLStatus {
	c.mu.Lock()
	defer c.mu.Unlock()
	s := &identity.WSLStatus{Exe: c.exe, Version: c.version}
	if err := c.connect(); err != nil {
		s.Error = err.Error()
	}
	s.Exe, s.Version = c.exe, c.version
	return s
}

func ws(id string) workspaceParams { return workspaceParams{WorkspaceID: id} }

func (c *Client) Create(workspaceID string) (identity.Identity, identity.PublicInfo, string, error) {
	return c.create(methodCreate, workspaceID)
}

func (c *Client) CreatePending(workspaceID string) (identity.Identity, identity.PublicInfo, string, error) {
	return c.create(methodCreatePending, workspaceID)
}

func (c *Client) create(method, workspaceID string) (identity.Identity, identity.PublicInfo, string, error) {
	var r identityResult
	if err := c.call(method, ws(workspaceID), &r); err != nil {
		return nil, identity.PublicInfo{}, "", err
	}
	id, err := c.identity(r)
	if err != nil {
		return nil, identity.PublicInfo{}, "", err
	}
	r.Info.Created = r.Created
	return id, r.Info, r.Warning, nil
}

func (c *Client) Load(workspaceID string) (identity.Identity, error) {
	var r identityResult
	if err := c.call(methodLoad, ws(workspaceID), &r); err != nil {
		return nil, err
	}
	return c.identity(r)
}

func (c *Client) LoadRetained(workspaceID string) ([]identity.Identity, error) {
	var r retainedResult
	if err := c.call(methodLoadRetained, ws(workspaceID), &r); err != nil {
		return nil, err
	}
	ids := make([]identity.Identity, 0, len(r.Identities))
	for _, ir := range r.Identities {
		id, err := c.identity(ir)
		if err != nil {
			for _, open := range ids {
				_ = open.Close()
			}
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, nil
}

func (c *Client) Info(workspaceID string) (identity.PublicInfo, error) {
	return c.info(methodInfo, workspaceID)
}

func (c *Client) PendingInfo(workspaceID string) (identity.PublicInfo, error) {
	return c.info(methodPendingInfo, workspaceID)
}

func (c *Client) info(method, workspaceID string) (identity.PublicInfo, error) {
	var r infoResult
	if err := c.call(method, ws(workspaceID), &r); err != nil {
		return identity.PublicInfo{}, err
	}
	r.Info.Created = r.Created
	return r.Info, nil
}

func (c *Client) PromotePending(workspaceID string) error {
	return c.call(methodPromotePending, ws(workspaceID), nil)
}

func (c *Client) CreateSigner(workspaceID string) (signing.Signer, identity.SignerInfo, string, error) {
	var r signerResult
	if err := c.call(methodCreateSigner, ws(workspaceID), &r); err != nil {
		return nil, identity.SignerInfo{}, "", err
	}
	r.Info.Created = r.Created
	return &remoteSigner{c: c, handle: r.Handle, public: r.Public}, r.Info, r.Warning, nil
}

func (c *Client) LoadSigner(workspaceID string) (signing.Signer, error) {
	var r signerResult
	if err := c.call(methodLoadSigner, ws(workspaceID), &r); err != nil {
		return nil, err
	}
	return &remoteSigner{c: c, handle: r.Handle, public: r.Public}, nil
}

func (c *Client) SignerInfo(workspaceID string) (identity.SignerInfo, error) {
	var r signerInfoResult
	if err := c.call(methodSignerInfo, ws(workspaceID), &r); err != nil {
		return identity.SignerInfo{}, err
	}
	r.Info.Created = r.Created
	return r.Info, nil
}

// Doctor reports the Windows side's diagnosis, and the bridge itself: a
// missing enbu.exe, disabled interop or another version is the problem to
// fix first.
func (c *Client) Doctor(ctx context.Context) identity.Diagnosis {
	status := c.status()
	if status.Error != "" {
		return identity.Diagnosis{Backend: "windows", Reason: status.Error, WSL: status}
	}
	var d identity.Diagnosis
	if err := c.call(methodDoctor, struct{}{}, &d); err != nil {
		status.Error = err.Error()
		return identity.Diagnosis{Backend: "windows", Reason: status.Error, WSL: status}
	}
	d.WSL = status
	return d
}

func (c *Client) identity(r identityResult) (identity.Identity, error) {
	parsed, err := enbuage.ParseRecipient(r.Recipient)
	if err != nil {
		return nil, fmt.Errorf("the Windows enbu.exe returned an invalid recipient: %w", err)
	}
	recipient, ok := parsed.(identity.Recipient)
	if !ok {
		return nil, errors.New("the Windows enbu.exe returned an invalid recipient")
	}
	return &remoteIdentity{c: c, handle: r.Handle, recipient: recipient}, nil
}

func (c *Client) release(h uint64) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn == nil {
		return nil // the process is gone, and its handles with it
	}
	return c.roundTrip(methodClose, handleParams{Handle: h}, nil)
}

type remoteIdentity struct {
	c         *Client
	handle    uint64
	recipient identity.Recipient
}

func (r *remoteIdentity) Unwrap(stanzas []*age.Stanza) ([]byte, error) {
	var res unwrapResult
	if err := r.c.call(methodUnwrap, unwrapParams{Handle: r.handle, Stanzas: stanzas}, &res); err != nil {
		return nil, err
	}
	return res.FileKey, nil
}

func (r *remoteIdentity) Recipient() identity.Recipient { return r.recipient }
func (r *remoteIdentity) Close() error                  { return r.c.release(r.handle) }

type remoteSigner struct {
	c      *Client
	handle uint64
	public signing.PublicKey
}

func (s *remoteSigner) Public() signing.PublicKey { return s.public }

func (s *remoteSigner) Sign(domain string, body []byte) ([]byte, error) {
	var res signResult
	if err := s.c.call(methodSign, signParams{Handle: s.handle, Domain: domain, Body: body}, &res); err != nil {
		return nil, err
	}
	return res.Signature, nil
}

func (s *remoteSigner) Close() error { return s.c.release(s.handle) }

// Keyring is the OS keyring of Windows, for the entries the Windows side
// shares (the GitHub token).
func (c *Client) Keyring() *Keyring { return &Keyring{c: c} }

// Keyring implements keystore.Backend over the bridge.
type Keyring struct{ c *Client }

func (k *Keyring) Store(service, key string, secret []byte) error {
	return keyringError(k.c.call(methodKeyringStore, keyringParams{Service: service, Key: key, Secret: secret}, nil))
}

func (k *Keyring) Load(service, key string) ([]byte, error) {
	var r keyringResult
	if err := k.c.call(methodKeyringLoad, keyringParams{Service: service, Key: key}, &r); err != nil {
		return nil, keyringError(err)
	}
	return r.Secret, nil
}

func (k *Keyring) Delete(service, key string) error {
	return keyringError(k.c.call(methodKeyringDelete, keyringParams{Service: service, Key: key}, nil))
}

// keyringError reports a bridge that cannot be reached as a missing keyring,
// so the token store says what to fix instead of an internal error.
func keyringError(err error) error {
	if err == nil || !errors.Is(err, identity.ErrUnavailable) || errors.Is(err, keystore.ErrLocked) || errors.Is(err, keystore.ErrNoKeyring) {
		return err
	}
	return fmt.Errorf("%w: %w", keystore.ErrNoKeyring, err)
}
