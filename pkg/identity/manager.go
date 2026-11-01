package identity

import (
	"bytes"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/enbu-net/enbu/pkg/fsutil"

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
	// EnclaveKey is the Secure Enclave's wrapped private key: only the Secure
	// Enclave that created it can use it.
	EnclaveKey []byte `json:"enclave_key,omitempty"`
	// The ML-KEM-768 seed of a hybrid hardware identity: sealed by the TPM,
	// sealed to the Secure Enclave key (EnclaveSeal), or kept in the OS keyring
	// under PQReference when the backend cannot seal.
	PQReference    string `json:"pq_reference,omitempty"`
	TPMSealPublic  []byte `json:"tpm_seal_public,omitempty"`
	TPMSealPrivate []byte `json:"tpm_seal_private,omitempty"`
	EnclaveSeal    []byte `json:"enclave_seal,omitempty"`
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

// SeedSealer is a hardware backend that can keep the ML-KEM-768 seed of a
// hybrid identity bound to the device. A backend without it leaves the seed in
// the OS keyring.
type SeedSealer interface {
	SealSeed(md *Metadata, seed []byte) error
	UnsealSeed(md *Metadata) ([]byte, error)
}

type Manager struct {
	Dir      string
	Mode     string
	Vault    Vault
	Hardware HardwareBackend
	// Classical makes Create generate the pre-hybrid keys (X25519, or P-256 on
	// hardware), for a workspace whose other members still run an enbu that
	// cannot read hybrid recipients. New identities are hybrid otherwise.
	Classical bool
}

const (
	algX25519      = "X25519"
	algMLKEMX25519 = "MLKEM768-X25519"
	algP256        = "P-256"
	algMLKEMP256   = "MLKEM768-P256"
	classicalFlag  = "ENBU_IDENTITY_CLASSICAL"
)

// hardwareAlgorithm reports whether alg names a hardware P-256 identity, alone
// or paired with an ML-KEM-768 seed.
func hardwareAlgorithm(alg string) bool { return alg == algP256 || alg == algMLKEMP256 }

func New() *Manager {
	return &Manager{Dir: filepath.Join(config.DataDir(), "identities"), Mode: os.Getenv("ENBU_IDENTITY_BACKEND"),
		Vault: &keystore.KeyringBackend{}, Hardware: platformHardware(), Classical: os.Getenv(classicalFlag) == "1"}
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

// slotPath names the identity that replaces the current one during a key
// update ("next") and the one it replaced ("previous").
func (m *Manager) slotPath(workspaceID, slot string) string {
	p := m.Path(workspaceID)
	return p[:len(p)-len(".json")] + "." + slot + ".json"
}

func (m *Manager) read(workspaceID string) (*Metadata, error) { return m.readPath(m.Path(workspaceID)) }

func (m *Manager) readPath(path string) (*Metadata, error) {
	b, err := os.ReadFile(path)
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

func (m *Manager) Load(workspaceID string) (Identity, error) { return m.loadPath(m.Path(workspaceID)) }

func (m *Manager) loadPath(path string) (Identity, error) {
	mode, err := m.mode()
	if err != nil {
		return nil, err
	}
	md, err := m.readPath(path)
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
		if md.Algorithm == algMLKEMP256 {
			if id, err = m.hybridHardware(id, md, nil); err != nil {
				return nil, fmt.Errorf("loading saved hardware identity: %w", err)
			}
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
	return m.create(m.Path(workspaceID), m.Classical)
}

func (m *Manager) create(path string, classical bool) (id Identity, info PublicInfo, warning string, err error) {
	mode, err := m.mode()
	if err != nil {
		return nil, info, "", err
	}
	if err := os.MkdirAll(m.Dir, 0o700); err != nil {
		return nil, info, "", err
	}
	lock, err := acquireCreationLock(path + ".lockfile")
	if err != nil {
		return nil, info, "", fmt.Errorf("identity creation lock (%s): %w", path+".lockfile", err)
	}
	defer func() { _ = lock.Close() }()
	if _, err := os.Stat(path); err == nil {
		id, err := m.loadPath(path)
		if err != nil {
			return nil, info, "", err
		}
		md, err := m.readPath(path)
		if err != nil {
			_ = id.Close()
			return nil, info, "", err
		}
		return id, md.PublicInfo, "", nil
	} else if !errors.Is(err, fs.ErrNotExist) {
		return nil, info, "", err
	}
	var md *Metadata
	if mode != "keyring" {
		d := Diagnosis{Reason: "hardware backend unavailable"}
		if m.Hardware != nil {
			d = m.Hardware.Probe()
		}
		if d.Available {
			id, md, err = m.Hardware.Create()
			if err != nil {
				return nil, info, "", err
			}
			if !classical {
				seed := make([]byte, mlkem.SeedSize)
				if _, err := rand.Read(seed); err != nil {
					m.deleteHardware(md)
					return nil, info, "", err
				}
				if id, err = m.hybridHardware(id, md, seed); err != nil {
					m.deleteHardware(md)
					return nil, info, "", err
				}
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
		alg, secret, err := generateKeyringIdentity(classical)
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
		} else {
			m.deleteHardware(md)
		}
		return nil, info, warning, err
	}
	info = md.PublicInfo
	info.Created = true
	return id, info, warning, nil
}

// hybridHardware pairs a loaded hardware P-256 identity with its ML-KEM-768
// seed. With a seed it stores the seed (sealed by the TPM, or in the keyring)
// and turns md into hybrid metadata; without one it reads the stored seed.
// The classical identity is consumed: on error its hardware key is closed.
func (m *Manager) hybridHardware(id Identity, md *Metadata, seed []byte) (Identity, error) {
	t, ok := id.(*taggedIdentity)
	if !ok {
		_ = id.Close()
		return nil, errors.New("hardware identity is not a P-256 key")
	}
	var err error
	if seed != nil {
		err = m.storeSeed(md, seed)
	} else {
		seed, err = m.loadSeed(md)
	}
	if err != nil {
		_ = id.Close()
		return nil, err
	}
	h, err := NewHybridHardwareIdentity(t.key, seed)
	clear(seed)
	if err != nil {
		_ = id.Close()
		return nil, err
	}
	if md.Algorithm != algMLKEMP256 {
		md.Algorithm, md.Recipient = algMLKEMP256, h.Recipient().String()
	}
	return h, nil
}

func (m *Manager) storeSeed(md *Metadata, seed []byte) error {
	if sealer, ok := m.Hardware.(SeedSealer); ok {
		return sealer.SealSeed(md, seed)
	}
	if m.Vault == nil {
		return unavailable("OS keyring unavailable for the ML-KEM seed", nil)
	}
	ref := make([]byte, 24)
	if _, err := rand.Read(ref); err != nil {
		return err
	}
	md.PQReference = hex.EncodeToString(ref)
	if err := m.Vault.Store(vaultService, md.PQReference, seed); err != nil {
		return keyringError("saving ML-KEM seed", err)
	}
	return nil
}

func (m *Manager) loadSeed(md *Metadata) ([]byte, error) {
	if len(md.TPMSealPublic) > 0 || len(md.EnclaveSeal) > 0 {
		sealer, ok := m.Hardware.(SeedSealer)
		if !ok {
			return nil, errors.New("hardware backend cannot unseal the ML-KEM seed")
		}
		return sealer.UnsealSeed(md)
	}
	if md.PQReference == "" {
		return nil, errors.New("hybrid identity metadata has no ML-KEM seed")
	}
	if m.Vault == nil {
		return nil, unavailable("keyring unavailable", nil)
	}
	seed, err := m.Vault.Load(vaultService, md.PQReference)
	if err != nil {
		return nil, keyringError("loading ML-KEM seed", err)
	}
	return seed, nil
}

// deleteHardware removes what a hardware identity left behind outside its
// metadata, on a creation that did not finish.
func (m *Manager) deleteHardware(md *Metadata) {
	if md.PQReference != "" && m.Vault != nil {
		_ = m.Vault.Delete(vaultService, md.PQReference)
	}
	if cleanup, ok := m.Hardware.(interface{ Delete(*Metadata) error }); ok {
		_ = cleanup.Delete(md)
	}
}

// generateKeyringIdentity returns the algorithm and encoded secret key of a
// new software identity.
func generateKeyringIdentity(classical bool) (string, string, error) {
	if !classical {
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

// CreatePending creates, or reuses, a hybrid identity that replaces the current
// one once an admin approves the key update. Until then both are loaded.
func (m *Manager) CreatePending(workspaceID string) (Identity, PublicInfo, string, error) {
	if _, err := m.read(workspaceID); err != nil {
		return nil, PublicInfo{}, "", err
	}
	return m.create(m.slotPath(workspaceID, "next"), false)
}

// PendingInfo describes the identity waiting for approval of a key update.
func (m *Manager) PendingInfo(workspaceID string) (PublicInfo, error) {
	md, err := m.readPath(m.slotPath(workspaceID, "next"))
	if err != nil {
		return PublicInfo{}, err
	}
	return md.PublicInfo, nil
}

// LoadRetained loads the identities besides the current one that can still
// decrypt: the pending one of a key update, and the one a key update
// replaced, which revisions written before the update are encrypted for.
func (m *Manager) LoadRetained(workspaceID string) ([]Identity, error) {
	var ids []Identity
	for _, slot := range []string{"next", "previous"} {
		id, err := m.loadPath(m.slotPath(workspaceID, slot))
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			for _, i := range ids {
				_ = i.Close()
			}
			return nil, fmt.Errorf("loading %s identity: %w", slot, err)
		}
		ids = append(ids, id)
	}
	return ids, nil
}

// PromotePending makes the pending identity current once the workspace lists
// its recipient. The current identity is kept as the previous one; an older
// previous identity is deleted with its key material.
func (m *Manager) PromotePending(workspaceID string) error {
	path, next, prev := m.Path(workspaceID), m.slotPath(workspaceID, "next"), m.slotPath(workspaceID, "previous")
	lock, err := acquireCreationLock(path + ".lockfile")
	if err != nil {
		return fmt.Errorf("identity creation lock (%s): %w", path+".lockfile", err)
	}
	defer func() { _ = lock.Close() }()
	if _, err := m.readPath(next); err != nil {
		return err
	}
	current, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	// The current identity replaces the previous one, whose key material
	// goes with it, unless the previous slot already holds the current
	// identity because an earlier promotion stopped between the two steps
	// below.
	if old, err := m.readPath(prev); err == nil {
		saved, err := os.ReadFile(prev)
		if err != nil {
			return err
		}
		if !bytes.Equal(saved, current) {
			m.deleteKeyMaterial(old)
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	// Copy, then replace: each step is one atomic rename, so the current
	// identity exists at every point, even if enbu or the machine stops in
	// between. Moving it away first would leave the workspace without one.
	// Until the rename, the previous slot duplicates the current identity;
	// the comparison above keeps a rerun from deleting its key material, and
	// if the pending identity is gone by then the duplicate is harmless.
	if current != nil {
		if err := writeFileAtomic(prev, current); err != nil {
			return err
		}
	}
	return renameFile(next, path)
}

func (m *Manager) deleteKeyMaterial(md *Metadata) {
	if md.Backend == "keyring" {
		if m.Vault != nil {
			_ = m.Vault.Delete(vaultService, md.Reference)
		}
		return
	}
	m.deleteHardware(md)
}

// renameFile replaces files in the identity directory; tests swap it to make a
// rename fail.
var renameFile = fsutil.Rename

func saveMetadata(path string, md *Metadata) error { return saveJSON(path, md) }

func saveJSON(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(path, b)
}

// writeFileAtomic replaces path with b through a synced temporary file.
func writeFileAtomic(path string, b []byte) error {
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
	return renameFile(f.Name(), path)
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
