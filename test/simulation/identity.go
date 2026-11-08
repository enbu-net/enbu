package simulation

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"io/fs"

	agecrypto "filippo.io/age"
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
	age     string
	signing []byte
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

func (k *Keys) Load(ws string) (*identity.Device, error) {
	m := k.state(ws)
	if m.age == "" {
		return nil, fs.ErrNotExist
	}
	id, err := agecrypto.ParseHybridIdentity(m.age)
	if err != nil {
		return nil, err
	}
	return &identity.Device{Identity: identity.FromHybrid(id), Signer: signing.NewEd25519Signer(ed25519.PrivateKey(m.signing))}, nil
}

// Signer returns the signing key of ws, for drivers that sign on the device's behalf.
func (k *Keys) Signer(ws string) (signing.Signer, error) {
	d, err := k.Load(ws)
	if err != nil {
		return nil, err
	}
	return d.Signer, nil
}

func keyInfo(d *identity.Device) identity.PublicInfo {
	id := d.Signer.Public().DeviceID()
	return identity.PublicInfo{Backend: "keyring", Algorithm: "MLKEM768-X25519", Recipient: d.Identity.Recipient().String(),
		DeviceID: string(id), Fingerprint: id.Fingerprint()}
}

func (k *Keys) Create(ws string) (*identity.Device, identity.PublicInfo, string, error) {
	m := k.state(ws)
	created := m.age == ""
	if created {
		if err := k.Tape.Value("identity", []any{k.Device, ws}, func() (any, error) {
			i, e := agecrypto.GenerateHybridIdentity()
			if e != nil {
				return nil, e
			}
			return i.String(), nil
		}, &m.age); err != nil {
			return nil, identity.PublicInfo{}, "", err
		}
		if err := k.Tape.Value("signing-key", []any{k.Device, ws}, func() (any, error) {
			_, p, e := ed25519.GenerateKey(rand.Reader)
			return []byte(p), e
		}, &m.signing); err != nil {
			return nil, identity.PublicInfo{}, "", err
		}
	}
	d, err := k.Load(ws)
	if err != nil {
		return nil, identity.PublicInfo{}, "", err
	}
	info := keyInfo(d)
	info.Created = created
	return d, info, "", nil
}

func (k *Keys) Info(ws string) (identity.PublicInfo, error) {
	d, err := k.Load(ws)
	if err != nil {
		return identity.PublicInfo{}, err
	}
	return keyInfo(d), nil
}

func (*Keys) Doctor(context.Context) identity.Diagnosis {
	return identity.Diagnosis{FallbackAvailable: true}
}
