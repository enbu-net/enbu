package simulation

import (
	"crypto/ed25519"
	"crypto/rand"
	agecrypto "filippo.io/age"
	"github.com/enbu-net/enbu/pkg/identity"
	"github.com/enbu-net/enbu/pkg/signing"
	"io/fs"
	"strings"
)

// Keys contains only synthetic identities generated for this simulation. Never
// point a simulation at a real identity backend or a real workspace.
type Keys struct {
	Tape             *Tape
	Device           int
	current, pending string
	retired          []string
	signing          []byte
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
func (k *Keys) Load(string) (identity.Identity, error) {
	if k.current == "" {
		return nil, fs.ErrNotExist
	}
	return parseKey(k.current)
}
func keyInfo(id identity.Identity) identity.PublicInfo {
	return identity.PublicInfo{Backend: "keyring", Recipient: id.Recipient().String(), Algorithm: "simulation software"}
}
func (k *Keys) Create(ws string) (identity.Identity, identity.PublicInfo, string, error) {
	if k.current == "" {
		e := k.Tape.Value("identity", []any{k.Device, ws}, func() (any, error) {
			i, e := agecrypto.GenerateX25519Identity()
			if e != nil {
				return nil, e
			}
			return i.String(), nil
		}, &k.current)
		if e != nil {
			return nil, identity.PublicInfo{}, "", e
		}
	}
	id, e := k.Load(ws)
	if e != nil {
		return nil, identity.PublicInfo{}, "", e
	}
	return id, keyInfo(id), "", nil
}
func (k *Keys) Info(ws string) (identity.PublicInfo, error) {
	id, e := k.Load(ws)
	if e != nil {
		return identity.PublicInfo{}, e
	}
	defer func() { _ = id.Close() }()
	return keyInfo(id), nil
}
func (*Keys) Doctor() identity.Diagnosis { return identity.Diagnosis{FallbackAvailable: true} }
func (k *Keys) LoadSigner(string) (signing.Signer, error) {
	if len(k.signing) == 0 {
		return nil, fs.ErrNotExist
	}
	return signing.NewEd25519Signer(ed25519.PrivateKey(k.signing)), nil
}
func signerInfo(s signing.Signer) identity.SignerInfo {
	id := s.Public().DeviceID()
	return identity.SignerInfo{Backend: "keyring", Algorithm: "Ed25519", DeviceID: id, Fingerprint: id.Fingerprint()}
}
func (k *Keys) CreateSigner(ws string) (signing.Signer, identity.SignerInfo, string, error) {
	if len(k.signing) == 0 {
		e := k.Tape.Value("signing-key", []any{k.Device, ws}, func() (any, error) { _, p, e := ed25519.GenerateKey(rand.Reader); return []byte(p), e }, &k.signing)
		if e != nil {
			return nil, identity.SignerInfo{}, "", e
		}
	}
	s, e := k.LoadSigner(ws)
	if e != nil {
		return nil, identity.SignerInfo{}, "", e
	}
	return s, signerInfo(s), "", nil
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
	if k.pending == "" {
		e := k.Tape.Value("pending-key", []any{k.Device, ws}, func() (any, error) {
			id, e := agecrypto.GenerateHybridIdentity()
			if e != nil {
				return nil, e
			}
			return id.String(), nil
		}, &k.pending)
		if e != nil {
			return nil, identity.PublicInfo{}, "", e
		}
	}
	id, e := parseKey(k.pending)
	if e != nil {
		return nil, identity.PublicInfo{}, "", e
	}
	return id, keyInfo(id), "", nil
}
func (k *Keys) PendingInfo(string) (identity.PublicInfo, error) {
	if k.pending == "" {
		return identity.PublicInfo{}, fs.ErrNotExist
	}
	id, e := parseKey(k.pending)
	if e != nil {
		return identity.PublicInfo{}, e
	}
	defer func() { _ = id.Close() }()
	return keyInfo(id), nil
}
func (k *Keys) PromotePending(string) error {
	if k.pending == "" {
		return fs.ErrNotExist
	}
	k.retired = append(k.retired, k.current)
	k.current, k.pending = k.pending, ""
	return nil
}
func (k *Keys) LoadRetained(string) ([]identity.Identity, error) {
	raw := append([]string(nil), k.retired...)
	if k.pending != "" {
		raw = append(raw, k.pending)
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
