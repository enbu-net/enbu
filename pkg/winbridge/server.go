package winbridge

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"filippo.io/age"
	"github.com/enbu-net/enbu/pkg/identity"
	"github.com/enbu-net/enbu/pkg/keystore"
	"github.com/enbu-net/enbu/pkg/signing"
)

// Store is what the bridge exposes of this device's keys: the app's identity
// store. identity.Manager implements it.
type Store interface {
	Create(workspaceID string) (*identity.Device, identity.PublicInfo, string, error)
	Load(workspaceID string) (*identity.Device, error)
	Info(workspaceID string) (identity.PublicInfo, error)
	Doctor(context.Context) identity.Diagnosis
}

// KeyringEntry is one OS keyring entry the bridge shares, such as the GitHub
// token. Identity keys are never shared: they stay behind Store.
type KeyringEntry struct{ Service, Key string }

// Server answers one WSL enbu on r and w. Loaded identities and signers stay
// open in this process until the WSL side closes them or the stream ends, so
// a TPM connection is reused for one command.
type Server struct {
	Version    string
	Identities Store
	Keyring    keystore.Backend
	Entries    []KeyringEntry

	handles map[uint64]io.Closer
	next    uint64
}

// Serve runs until r ends. Every handle still open is closed then.
func (s *Server) Serve(ctx context.Context, r io.Reader, w io.Writer) error {
	s.handles = map[uint64]io.Closer{}
	defer s.closeAll()
	dec := json.NewDecoder(bufio.NewReader(r))
	out := bufio.NewWriter(w)
	enc := json.NewEncoder(out)
	greeted := false
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		var req request
		if err := dec.Decode(&req); err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return fmt.Errorf("reading bridge request: %w", err)
		}
		var result any
		var err error
		switch {
		case req.Method == methodHello:
			result, err = s.hello(req.Params)
			greeted = err == nil
		case !greeted:
			err = errors.New("the bridge expects hello first")
		default:
			result, err = s.dispatch(ctx, req.Method, req.Params)
		}
		resp := response{ID: req.ID}
		if err != nil {
			resp.Error = encodeError(err)
		} else if resp.Result, err = json.Marshal(result); err != nil {
			resp.Error = encodeError(err)
		}
		if err := enc.Encode(resp); err != nil {
			return fmt.Errorf("writing bridge response: %w", err)
		}
		if err := out.Flush(); err != nil {
			return fmt.Errorf("writing bridge response: %w", err)
		}
	}
}

func (s *Server) hello(raw json.RawMessage) (any, error) {
	var p helloParams
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, err
	}
	if p.Protocol != Protocol {
		return nil, fmt.Errorf("%s: WSL enbu speaks %d, Windows enbu.exe %s speaks %d; install the same enbu version in Windows and in WSL", errIncompatibleProtocol, p.Protocol, s.Version, Protocol)
	}
	return helloResult{Protocol: Protocol, Version: s.Version}, nil
}

func (s *Server) dispatch(ctx context.Context, method string, raw json.RawMessage) (any, error) {
	switch method {
	case methodCreate:
		p, err := decode[workspaceParams](raw)
		if err != nil {
			return nil, err
		}
		d, info, warning, err := s.Identities.Create(p.WorkspaceID)
		if err != nil {
			return nil, err
		}
		r := s.device(d, info)
		r.Warning = warning
		return r, nil
	case methodLoad:
		p, err := decode[workspaceParams](raw)
		if err != nil {
			return nil, err
		}
		d, err := s.Identities.Load(p.WorkspaceID)
		if err != nil {
			return nil, err
		}
		return s.device(d, identity.PublicInfo{}), nil
	case methodInfo:
		p, err := decode[workspaceParams](raw)
		if err != nil {
			return nil, err
		}
		i, err := s.Identities.Info(p.WorkspaceID)
		if err != nil {
			return nil, err
		}
		return infoResult{Info: i, Created: i.Created}, nil
	case methodUnwrap:
		p, err := decode[unwrapParams](raw)
		if err != nil {
			return nil, err
		}
		id, err := handle[age.Identity](s, p.Handle)
		if err != nil {
			return nil, err
		}
		key, err := id.Unwrap(p.Stanzas)
		if err != nil {
			return nil, err
		}
		return unwrapResult{FileKey: key}, nil
	case methodSign:
		p, err := decode[signParams](raw)
		if err != nil {
			return nil, err
		}
		signer, err := handle[signing.Signer](s, p.Handle)
		if err != nil {
			return nil, err
		}
		sig, err := signer.Sign(p.Domain, p.Body)
		if err != nil {
			return nil, err
		}
		return signResult{Signature: sig}, nil
	case methodClose:
		p, err := decode[handleParams](raw)
		if err != nil {
			return nil, err
		}
		c, ok := s.handles[p.Handle]
		if !ok {
			return struct{}{}, nil
		}
		delete(s.handles, p.Handle)
		return struct{}{}, c.Close()
	case methodDoctor:
		return s.Identities.Doctor(ctx), nil
	case methodKeyringStore, methodKeyringLoad, methodKeyringDelete:
		p, err := decode[keyringParams](raw)
		if err != nil {
			return nil, err
		}
		if !s.shared(p.Service, p.Key) {
			return nil, errors.New(errKeyringEntryForbidden)
		}
		switch method {
		case methodKeyringStore:
			return struct{}{}, s.Keyring.Store(p.Service, p.Key, p.Secret)
		case methodKeyringLoad:
			secret, err := s.Keyring.Load(p.Service, p.Key)
			if err != nil {
				return nil, err
			}
			return keyringResult{Secret: secret}, nil
		default:
			return struct{}{}, s.Keyring.Delete(p.Service, p.Key)
		}
	}
	return nil, fmt.Errorf("%s %q", errUnknownMethod, method)
}

func (s *Server) device(d *identity.Device, info identity.PublicInfo) deviceResult {
	return deviceResult{Identity: s.keep(d.Identity), Recipient: d.Identity.Recipient().String(),
		Signer: s.keep(d.Signer), Public: d.Signer.Public(), Info: info, Created: info.Created}
}

func (s *Server) keep(c io.Closer) uint64 {
	s.next++
	s.handles[s.next] = c
	return s.next
}

func (s *Server) shared(service, key string) bool {
	if s.Keyring == nil {
		return false
	}
	for _, e := range s.Entries {
		if e.Service == service && e.Key == key {
			return true
		}
	}
	return false
}

func (s *Server) closeAll() {
	for h, c := range s.handles {
		_ = c.Close()
		delete(s.handles, h)
	}
}

func handle[T any](s *Server, h uint64) (T, error) {
	v, ok := s.handles[h].(T)
	if !ok {
		var zero T
		return zero, fmt.Errorf("%s %d", errUnknownHandle, h)
	}
	return v, nil
}

func decode[T any](raw json.RawMessage) (T, error) {
	var v T
	if err := json.Unmarshal(raw, &v); err != nil {
		return v, fmt.Errorf("invalid bridge request: %w", err)
	}
	return v, nil
}
