package simulation

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"io/fs"
	"strings"

	agecrypto "filippo.io/age"
	"github.com/enbu-net/enbu/pkg/age"
	"github.com/enbu-net/enbu/pkg/identity"
	"github.com/enbu-net/enbu/pkg/signing"
)

// Keys contains only synthetic identities generated for this simulation. Never
// point a simulation at a real identity backend or a real workspace.
type Keys struct {
	Tape       *Tape
	Device     int
	workspaces map[string]*keyMaterial
}
type keyMaterial struct {
	current, pending string
	previous         string
	signing          []byte
}

func (k *Keys) state(ws string) *keyMaterial {
	if k.workspaces == nil {
		k.workspaces = map[string]*keyMaterial{}
	}
	if k.workspaces[ws] == nil {
		k.workspaces[ws] = &keyMaterial{}
	}
	return k.workspaces[ws]
}
func parseKey(raw string) (identity.Identity, error) {
	if strings.HasPrefix(raw, "AGE-SECRET-KEY-PQ-") {
		k, e := agecrypto.ParseHybridIdentity(raw)
		if e != nil {
			return nil, e
		}
		return identity.FromHybrid(k), nil
	}
	k, e := agecrypto.ParseX25519Identity(raw)
	if e != nil {
		return nil, e
	}
	return identity.FromX25519(k), nil
}
func (k *Keys) Load(ws string) (identity.Identity, error) {
	if k.state(ws).current == "" {
		return nil, fs.ErrNotExist
	}
	return parseKey(k.state(ws).current)
}
func keyInfo(id identity.Identity) identity.PublicInfo {
	algorithm := "X25519"
	if age.IsPostQuantum(id.Recipient().String()) {
		algorithm = "ML-KEM-768 + X25519"
	}
	return identity.PublicInfo{Backend: "keyring", Recipient: id.Recipient().String(), Algorithm: algorithm}
}
func (k *Keys) Create(ws string) (identity.Identity, identity.PublicInfo, string, error) {
	created := k.state(ws).current == ""
	if k.state(ws).current == "" {
		e := k.Tape.Value("identity", []any{k.Device, ws}, func() (any, error) {
			i, e := agecrypto.GenerateX25519Identity()
			if e != nil {
				return nil, e
			}
			return i.String(), nil
		}, &k.state(ws).current)
		if e != nil {
			return nil, identity.PublicInfo{}, "", e
		}
	}
	id, e := k.Load(ws)
	if e != nil {
		return nil, identity.PublicInfo{}, "", e
	}
	info := keyInfo(id)
	info.Created = created
	return id, info, "", nil
}
func (k *Keys) Info(ws string) (identity.PublicInfo, error) {
	id, e := k.Load(ws)
	if e != nil {
		return identity.PublicInfo{}, e
	}
	defer func() { _ = id.Close() }()
	return keyInfo(id), nil
}
func (*Keys) Doctor(context.Context) identity.Diagnosis {
	return identity.Diagnosis{FallbackAvailable: true}
}
func (k *Keys) LoadSigner(ws string) (signing.Signer, error) {
	if len(k.state(ws).signing) == 0 {
		return nil, fs.ErrNotExist
	}
	return signing.NewEd25519Signer(ed25519.PrivateKey(k.state(ws).signing)), nil
}
func signerInfo(s signing.Signer) identity.SignerInfo {
	id := s.Public().DeviceID()
	return identity.SignerInfo{Backend: "keyring", Algorithm: "Ed25519", DeviceID: id, Fingerprint: id.Fingerprint()}
}
func (k *Keys) CreateSigner(ws string) (signing.Signer, identity.SignerInfo, string, error) {
	created := len(k.state(ws).signing) == 0
	if len(k.state(ws).signing) == 0 {
		e := k.Tape.Value("signing-key", []any{k.Device, ws}, func() (any, error) { _, p, e := ed25519.GenerateKey(rand.Reader); return []byte(p), e }, &k.state(ws).signing)
		if e != nil {
			return nil, identity.SignerInfo{}, "", e
		}
	}
	s, e := k.LoadSigner(ws)
	if e != nil {
		return nil, identity.SignerInfo{}, "", e
	}
	info := signerInfo(s)
	info.Created = created
	return s, info, "", nil
}
func (k *Keys) SignerInfo(ws string) (identity.SignerInfo, error) {
	s, e := k.LoadSigner(ws)
	if e != nil {
		return identity.SignerInfo{}, e
	}
	defer func() { _ = s.Close() }()
	return signerInfo(s), nil
}
func (k *Keys) CreatePending(ws string) (identity.Identity, identity.PublicInfo, string, error) {
	if k.state(ws).current == "" {
		return nil, identity.PublicInfo{}, "", fs.ErrNotExist
	}
	created := k.state(ws).pending == ""
	if k.state(ws).pending == "" {
		e := k.Tape.Value("pending-key", []any{k.Device, ws}, func() (any, error) {
			id, e := agecrypto.GenerateHybridIdentity()
			if e != nil {
				return nil, e
			}
			return id.String(), nil
		}, &k.state(ws).pending)
		if e != nil {
			return nil, identity.PublicInfo{}, "", e
		}
	}
	id, e := parseKey(k.state(ws).pending)
	if e != nil {
		return nil, identity.PublicInfo{}, "", e
	}
	info := keyInfo(id)
	info.Created = created
	return id, info, "", nil
}
func (k *Keys) PendingInfo(ws string) (identity.PublicInfo, error) {
	if k.state(ws).pending == "" {
		return identity.PublicInfo{}, fs.ErrNotExist
	}
	id, e := parseKey(k.state(ws).pending)
	if e != nil {
		return identity.PublicInfo{}, e
	}
	defer func() { _ = id.Close() }()
	return keyInfo(id), nil
}
func (k *Keys) PromotePending(ws string) error {
	if k.state(ws).pending == "" {
		return fs.ErrNotExist
	}
	k.state(ws).previous = k.state(ws).current
	k.state(ws).current, k.state(ws).pending = k.state(ws).pending, ""
	return nil
}
func (k *Keys) LoadRetained(ws string) ([]identity.Identity, error) {
	var raw []string
	if k.state(ws).pending != "" {
		raw = append(raw, k.state(ws).pending)
	}
	if k.state(ws).previous != "" {
		raw = append(raw, k.state(ws).previous)
	}
	var out []identity.Identity
	for _, s := range raw {
		id, e := parseKey(s)
		if e != nil {
			return nil, e
		}
		out = append(out, id)
	}
	return out, nil
}
