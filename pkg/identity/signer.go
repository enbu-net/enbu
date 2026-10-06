package identity

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"

	"github.com/enbu-net/enbu/pkg/signing"
)

// The signing key is a separate keypair from the encryption identity. It has
// its own metadata file and its own Keychain/TPM object.

const signerVaultPrefix = "signing-"

type SignerMetadata struct {
	Version    int               `json:"version"`
	Backend    string            `json:"backend"`
	Algorithm  string            `json:"algorithm"`
	Device     string            `json:"device,omitempty"`
	PublicKey  signing.PublicKey `json:"public_key"`
	DeviceID   signing.DeviceID  `json:"device_id"`
	Reference  string            `json:"reference,omitempty"`
	TPMPublic  []byte            `json:"tpm_public,omitempty"`
	TPMPrivate []byte            `json:"tpm_private,omitempty"`
	TPMName    []byte            `json:"tpm_name,omitempty"`
}

// SignerInfo is the public description of the local signing key.
type SignerInfo struct {
	Created     bool             `json:"-"`
	Backend     string           `json:"backend"`
	Algorithm   string           `json:"algorithm"`
	Device      string           `json:"device,omitempty"`
	DeviceID    signing.DeviceID `json:"device_id"`
	Fingerprint string           `json:"fingerprint"`
}

// SignerBackend is implemented by hardware backends that can hold a
// non-exportable P-256 signing key.
type SignerBackend interface {
	CreateSigner() (signing.Signer, *SignerMetadata, error)
	LoadSigner(*SignerMetadata) (signing.Signer, error)
}

func (md *SignerMetadata) info() SignerInfo {
	return SignerInfo{Backend: md.Backend, Algorithm: md.Algorithm, Device: md.Device, DeviceID: md.DeviceID, Fingerprint: md.DeviceID.Fingerprint()}
}

// SignerPath uses the same workspace hash as Path, so the two never collide.
func (m *Manager) SignerPath(workspaceID string) string {
	p := m.Path(workspaceID)
	return p[:len(p)-len(".json")] + ".signing.json"
}

func (m *Manager) readSigner(workspaceID string) (*SignerMetadata, error) {
	b, err := os.ReadFile(m.SignerPath(workspaceID))
	if err != nil {
		return nil, err
	}
	var md SignerMetadata
	if err := json.Unmarshal(b, &md); err != nil {
		return nil, fmt.Errorf("signing key metadata: %w", err)
	}
	if md.Version != 1 {
		return nil, fmt.Errorf("unsupported signing key metadata version %d", md.Version)
	}
	if md.Backend == "" || md.PublicKey.Validate() != nil || md.DeviceID != md.PublicKey.DeviceID() {
		return nil, errors.New("invalid signing key metadata")
	}
	return &md, nil
}

func (m *Manager) LoadSigner(workspaceID string) (signing.Signer, error) {
	mode, err := m.mode()
	if err != nil {
		return nil, err
	}
	md, err := m.readSigner(workspaceID)
	if err != nil {
		return nil, err
	}
	if mode == "hardware" && md.Backend == "keyring" || mode == "keyring" && md.Backend != "keyring" {
		return nil, fmt.Errorf("saved signing backend %s does not satisfy %s", md.Backend, mode)
	}
	var s signing.Signer
	if md.Backend == "keyring" {
		s, err = m.loadSoftwareSigner(md)
	} else {
		hw, ok := m.Hardware.(SignerBackend)
		if !ok {
			return nil, errors.New("saved hardware signing backend unavailable")
		}
		s, err = hw.LoadSigner(md)
		if err != nil {
			err = fmt.Errorf("loading saved hardware signing key: %w", err)
		}
	}
	if err != nil {
		return nil, err
	}
	// The loaded key must be the key the metadata (and thus the DeviceID) names.
	if got := s.Public(); got.Alg != md.PublicKey.Alg || string(got.Bytes) != string(md.PublicKey.Bytes) {
		_ = s.Close()
		return nil, errors.New("signing key does not match metadata")
	}
	return s, nil
}

func (m *Manager) loadSoftwareSigner(md *SignerMetadata) (signing.Signer, error) {
	if md.Algorithm != "Ed25519" || md.Reference == "" {
		return nil, errors.New("invalid keyring signing metadata")
	}
	if m.Vault == nil {
		return nil, errors.New("keyring unavailable")
	}
	secret, err := m.Vault.Load(vaultService, md.Reference)
	if err != nil {
		return nil, fmt.Errorf("loading saved keyring signing key: %w", err)
	}
	seed, err := hex.DecodeString(string(secret))
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, errors.New("saved keyring signing key is malformed")
	}
	return signing.NewEd25519Signer(ed25519.NewKeyFromSeed(seed)), nil
}

// CreateSigner reuses an existing signing key. Like Create, once creation has
// started a failure is returned rather than silently selecting another backend.
func (m *Manager) CreateSigner(workspaceID string) (s signing.Signer, info SignerInfo, warning string, err error) {
	mode, err := m.mode()
	if err != nil {
		return nil, info, "", err
	}
	path := m.SignerPath(workspaceID)
	if err := os.MkdirAll(m.Dir, 0o700); err != nil {
		return nil, info, "", err
	}
	lock, err := acquireCreationLock(path + ".lockfile")
	if err != nil {
		return nil, info, "", fmt.Errorf("signing key creation lock (%s): %w", path+".lockfile", err)
	}
	defer func() { _ = lock.Close() }()
	if _, err := os.Stat(path); err == nil {
		s, err := m.LoadSigner(workspaceID)
		if err != nil {
			return nil, info, "", err
		}
		md, err := m.readSigner(workspaceID)
		if err != nil {
			_ = s.Close()
			return nil, info, "", err
		}
		return s, md.info(), "", nil
	} else if !errors.Is(err, fs.ErrNotExist) {
		return nil, info, "", err
	}
	var md *SignerMetadata
	if mode != "keyring" {
		hw, ok := m.Hardware.(SignerBackend)
		reason := "hardware backend unavailable"
		available := false
		if ok {
			d := m.Hardware.Probe()
			available, reason = d.Available, d.Reason
		}
		if available {
			s, md, err = hw.CreateSigner()
			if err != nil {
				return nil, info, "", err
			}
		} else {
			if mode == "hardware" {
				return nil, info, "", fmt.Errorf("hardware signing key unavailable: %s", reason)
			}
			warning = "Hardware signing key unavailable: " + reason + "; using OS keyring (Ed25519)."
		}
	}
	if s == nil {
		s, md, err = m.createSoftwareSigner()
		if err != nil {
			return nil, info, warning, err
		}
	}
	md.Version = 1
	md.PublicKey = s.Public()
	md.DeviceID = md.PublicKey.DeviceID()
	if err := saveJSON(path, md); err != nil {
		_ = s.Close()
		if md.Backend == "keyring" {
			_ = m.Vault.Delete(vaultService, md.Reference)
		} else if cleanup, ok := m.Hardware.(interface{ DeleteSigner(*SignerMetadata) error }); ok {
			_ = cleanup.DeleteSigner(md)
		}
		return nil, info, warning, err
	}
	info = md.info()
	info.Created = true
	return s, info, warning, nil
}

func (m *Manager) createSoftwareSigner() (signing.Signer, *SignerMetadata, error) {
	if m.Vault == nil {
		return nil, nil, errors.New("OS keyring unavailable")
	}
	if probe, ok := m.Vault.(interface{ Probe() error }); ok {
		if err := probe.Probe(); err != nil {
			return nil, nil, fmt.Errorf("OS keyring unavailable: %w", err)
		}
	}
	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		return nil, nil, err
	}
	ref := make([]byte, 24)
	if _, err := rand.Read(ref); err != nil {
		return nil, nil, err
	}
	md := &SignerMetadata{Backend: "keyring", Algorithm: "Ed25519", Reference: signerVaultPrefix + hex.EncodeToString(ref)}
	if err := m.Vault.Store(vaultService, md.Reference, []byte(hex.EncodeToString(seed))); err != nil {
		return nil, nil, fmt.Errorf("saving OS keyring signing key: %w", err)
	}
	return signing.NewEd25519Signer(ed25519.NewKeyFromSeed(seed)), md, nil
}

// SignerInfo validates the saved signing key before reporting its public data.
func (m *Manager) SignerInfo(workspaceID string) (SignerInfo, error) {
	s, err := m.LoadSigner(workspaceID)
	if err != nil {
		return SignerInfo{}, err
	}
	defer func() { _ = s.Close() }()
	md, err := m.readSigner(workspaceID)
	if err != nil {
		return SignerInfo{}, err
	}
	return md.info(), nil
}
