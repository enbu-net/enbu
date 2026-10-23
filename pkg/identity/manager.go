package identity

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"filippo.io/age"
	"github.com/enbu-net/enbu/pkg/config"
	"github.com/enbu-net/enbu/pkg/keystore"
)

const vaultService = "enbu-identity-v1"

type Vault interface {
	Store(service, key string, value []byte) error
	Load(service, key string) ([]byte, error)
	Delete(service, key string) error
}

type Metadata struct {
	Version int `json:"version"`
	PublicInfo
	PublicKey  []byte `json:"public_key"`
	Reference  string `json:"reference,omitempty"`
	TPMPublic  []byte `json:"tpm_public,omitempty"`
	TPMPrivate []byte `json:"tpm_private,omitempty"`
	TPMName    []byte `json:"tpm_name,omitempty"`
}

type Diagnosis struct {
	Backend           string `json:"backend"`
	Device            string `json:"device,omitempty"`
	Available         bool   `json:"available"`
	Reason            string `json:"reason,omitempty"`
	FallbackAvailable bool   `json:"fallback_available"`
	FallbackReason    string `json:"fallback_reason,omitempty"`
}

type HardwareBackend interface {
	Probe() Diagnosis
	Create() (Identity, *Metadata, error)
	Load(*Metadata) (Identity, error)
}

type Manager struct {
	Dir      string
	Mode     string
	Vault    Vault
	Hardware HardwareBackend
	// PostQuantum makes Create generate a hybrid ML-KEM-768 + X25519 keyring
	// identity. It is an experiment: other members' enbu must accept age1pq1
	// recipients, and hardware-bound hybrid keys are not created yet.
	PostQuantum bool
}

const (
	algX25519       = "X25519"
	algMLKEMX25519  = "MLKEM768-X25519"
	postQuantumFlag = "ENBU_EXPERIMENTAL_PQ"
)

func New() *Manager {
	return &Manager{Dir: filepath.Join(config.DataDir(), "identities"), Mode: os.Getenv("ENBU_IDENTITY_BACKEND"),
		Vault: &keystore.KeyringBackend{}, Hardware: platformHardware(), PostQuantum: os.Getenv(postQuantumFlag) == "1"}
}

func (m *Manager) mode() (string, error) {
	switch m.Mode {
	case "", "auto":
		return "auto", nil
	case "hardware", "keyring":
		return m.Mode, nil
	default:
		return "", fmt.Errorf("invalid ENBU_IDENTITY_BACKEND %q (supported: auto, hardware, keyring)", m.Mode)
	}
}

// Path uses a hash so workspace IDs cannot escape the local identity directory.
func (m *Manager) Path(workspaceID string) string {
	sum := sha256.Sum256([]byte(workspaceID))
	return filepath.Join(m.Dir, hex.EncodeToString(sum[:])+".json")
}

func (m *Manager) read(workspaceID string) (*Metadata, error) {
	b, err := os.ReadFile(m.Path(workspaceID))
	if err != nil {
		return nil, err
	}
	var md Metadata
	if err := json.Unmarshal(b, &md); err != nil {
		return nil, fmt.Errorf("identity metadata: %w", err)
	}
	if md.Version != 1 {
		return nil, fmt.Errorf("unsupported identity metadata version %d", md.Version)
	}
	if md.Backend == "" || md.Recipient == "" || len(md.PublicKey) == 0 {
		return nil, errors.New("incomplete identity metadata")
	}
	return &md, nil
}

func (m *Manager) Load(workspaceID string) (Identity, error) {
	mode, err := m.mode()
	if err != nil {
		return nil, err
	}
	md, err := m.read(workspaceID)
	if err != nil {
		return nil, err
	}
	if mode == "hardware" && md.Backend == "keyring" || mode == "keyring" && md.Backend != "keyring" {
		return nil, fmt.Errorf("saved identity backend %s does not satisfy %s", md.Backend, mode)
	}
	var id Identity
	if md.Backend == "keyring" {
		if md.Algorithm != algX25519 && md.Algorithm != algMLKEMX25519 || md.Reference == "" {
			return nil, errors.New("invalid keyring metadata")
		}
		if m.Vault == nil {
			return nil, unavailable("keyring unavailable", nil)
		}
		secret, err := m.Vault.Load(vaultService, md.Reference)
		if err != nil {
			return nil, keyringError("loading saved keyring identity", err)
		}
		id, err = parseKeyringIdentity(md.Algorithm, string(secret))
		if err != nil {
			return nil, fmt.Errorf("saved keyring identity: %w", err)
		}
	} else {
		if m.Hardware == nil {
			return nil, unavailable("saved hardware backend unavailable", nil)
		}
		id, err = m.Hardware.Load(md)
		if err != nil {
			return nil, fmt.Errorf("loading saved hardware identity: %w", err)
		}
	}
	if id.Recipient().String() != md.Recipient || !publicKeyMatches(id, md.PublicKey) {
		_ = id.Close()
		return nil, errors.New("identity key does not match metadata")
	}
	return id, nil
}

func parseKeyringIdentity(alg, secret string) (Identity, error) {
	if alg == algMLKEMX25519 {
		key, err := age.ParseHybridIdentity(secret)
		if err != nil {
			return nil, err
		}
		return FromHybrid(key), nil
	}
	key, err := age.ParseX25519Identity(secret)
	if err != nil {
		return nil, err
	}
	return FromX25519(key), nil
}

func publicKeyMatches(id Identity, public []byte) bool {
	switch i := id.(type) {
	case *taggedIdentity:
		return string(i.key.PublicKey().Bytes()) == string(public)
	case *softwareIdentity:
		return string(i.Recipient().String()) == string(public)
	case *hybridSoftwareIdentity:
		return string(i.Recipient().String()) == string(public)
	default:
		return false
	}
}

// Create reuses only version 1 identities. The warning describes auto fallback.
// Once creation starts, all failures are returned without selecting another key.
func (m *Manager) Create(workspaceID string) (id Identity, info PublicInfo, warning string, err error) {
	mode, err := m.mode()
	if err != nil {
		return nil, info, "", err
	}
	path := m.Path(workspaceID)
	if err := os.MkdirAll(m.Dir, 0o700); err != nil {
		return nil, info, "", err
	}
	lock, err := acquireCreationLock(path + ".lockfile")
	if err != nil {
		return nil, info, "", fmt.Errorf("identity creation lock (%s): %w", path+".lockfile", err)
	}
	defer func() { _ = lock.Close() }()
	if _, err := os.Stat(path); err == nil {
		id, err := m.Load(workspaceID)
		if err != nil {
			return nil, info, "", err
		}
		md, err := m.read(workspaceID)
		if err != nil {
			_ = id.Close()
			return nil, info, "", err
		}
		return id, md.PublicInfo, "", nil
	} else if !errors.Is(err, fs.ErrNotExist) {
		return nil, info, "", err
	}
	var md *Metadata
	if m.PostQuantum && mode == "hardware" {
		return nil, info, "", errors.New("post-quantum hardware identities are not supported yet; use ENBU_IDENTITY_BACKEND=keyring")
	}
	if m.PostQuantum && mode == "auto" {
		warning = "Post-quantum identities are kept in the OS keyring (ML-KEM-768 + X25519); hardware-bound hybrid keys are not supported yet."
	} else if mode != "keyring" {
		d := Diagnosis{Reason: "hardware backend unavailable"}
		if m.Hardware != nil {
			d = m.Hardware.Probe()
		}
		if d.Available {
			id, md, err = m.Hardware.Create()
			if err != nil {
				return nil, info, "", err
			}
		} else {
			if mode == "hardware" {
				return nil, info, "", unavailable("hardware identity unavailable: "+d.Reason, nil)
			}
			warning = "Hardware identity unavailable: " + d.Reason + "; using OS keyring (X25519)."
		}
	}
	if id == nil {
		if m.Vault == nil {
			return nil, info, warning, unavailable("OS keyring unavailable", nil)
		}
		if probe, ok := m.Vault.(interface{ Probe() error }); ok {
			if err := probe.Probe(); err != nil {
				return nil, info, warning, unavailable("OS keyring unavailable", err)
			}
		}
		alg, secret, err := m.generateKeyringIdentity()
		if err != nil {
			return nil, info, warning, err
		}
		key, err := parseKeyringIdentity(alg, secret)
		if err != nil {
			return nil, info, warning, err
		}
		ref := make([]byte, 24)
		if _, err := rand.Read(ref); err != nil {
			return nil, info, warning, err
		}
		recipient := key.Recipient().String()
		md = &Metadata{Version: 1, PublicInfo: PublicInfo{Backend: "keyring", Algorithm: alg, Recipient: recipient},
			PublicKey: []byte(recipient), Reference: hex.EncodeToString(ref)}
		if err := m.Vault.Store(vaultService, md.Reference, []byte(secret)); err != nil {
			return nil, info, warning, keyringError("saving OS keyring identity", err)
		}
		id = key
	}
	md.Version = 1
	if err := saveMetadata(path, md); err != nil {
		_ = id.Close()
		if md.Backend == "keyring" {
			_ = m.Vault.Delete(vaultService, md.Reference)
		}
		if cleanup, ok := m.Hardware.(interface{ Delete(*Metadata) error }); ok && md.Backend != "keyring" {
			_ = cleanup.Delete(md)
		}
		return nil, info, warning, err
	}
	info = md.PublicInfo
	info.Created = true
	return id, info, warning, nil
}

// generateKeyringIdentity returns the algorithm and encoded secret key of a
// new software identity.
func (m *Manager) generateKeyringIdentity() (string, string, error) {
	if m.PostQuantum {
		key, err := age.GenerateHybridIdentity()
		if err != nil {
			return "", "", err
		}
		return algMLKEMX25519, key.String(), nil
	}
	key, err := age.GenerateX25519Identity()
	if err != nil {
		return "", "", err
	}
	return algX25519, key.String(), nil
}

func saveMetadata(path string, md *Metadata) error { return saveJSON(path, md) }

func saveJSON(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".identity-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(f.Name()) }()
	if _, err = f.Write(b); err == nil {
		err = f.Sync()
	}
	err = errors.Join(err, f.Close())
	if err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}

// Info validates the saved identity before reporting public information.
func (m *Manager) Info(workspaceID string) (PublicInfo, error) {
	id, err := m.Load(workspaceID)
	if err != nil {
		return PublicInfo{}, err
	}
	defer func() { _ = id.Close() }()
	md, err := m.read(workspaceID)
	if err != nil {
		return PublicInfo{}, err
	}
	return md.PublicInfo, nil
}

// Doctor probes capabilities and keyring access without creating a durable key.
func (m *Manager) Doctor() Diagnosis {
	d := Diagnosis{Reason: "hardware backend unavailable"}
	if m.Hardware != nil {
		d = m.Hardware.Probe()
	}
	if m.Vault == nil {
		d.FallbackReason = "OS keyring unavailable"
		return d
	}
	if probe, ok := m.Vault.(interface{ Probe() error }); ok {
		if err := probe.Probe(); err != nil {
			d.FallbackReason = err.Error()
		} else {
			d.FallbackAvailable = true
		}
		return d
	}
	_, err := m.Vault.Load(vaultService, "probe")
	if err == nil || errors.Is(err, fs.ErrNotExist) {
		d.FallbackAvailable = true
	} else {
		d.FallbackReason = err.Error()
	}
	return d
}
