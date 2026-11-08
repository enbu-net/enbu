package identity

import (
	"context"
	"crypto/ed25519"
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
	"runtime"

	"filippo.io/age"
	"github.com/enbu-net/enbu/pkg/clock"
	"github.com/enbu-net/enbu/pkg/config"
	"github.com/enbu-net/enbu/pkg/fsutil"
	"github.com/enbu-net/enbu/pkg/keystore"
	"github.com/enbu-net/enbu/pkg/signing"
)

const vaultService = "enbu-identity-v1"

const (
	algSoftware = "MLKEM768-X25519"
	algHardware = "MLKEM768-P256"

	backendKeyring = "keyring"
	backendCreds   = "systemd-creds"
)

// Device holds this device's keys for one workspace: the age identity it
// decrypts with and the separate key it signs with.
type Device struct {
	Identity Identity
	Signer   signing.Signer
}

func (d *Device) Close() error {
	return errors.Join(d.Identity.Close(), d.Signer.Close())
}

// Metadata is the file that finds a device's keys again. It holds no private
// key material: a software device names its vault entry, a hardware device
// keeps the blobs only its own TPM or Secure Enclave can use.
type Metadata struct {
	Backend    string            `json:"backend"`
	Algorithm  string            `json:"algorithm"`
	Device     string            `json:"device,omitempty"`
	Recipient  string            `json:"recipient"`
	SigningKey signing.PublicKey `json:"signing_key"`
	// Reference names the vault entry of a software device.
	Reference string `json:"reference,omitempty"`
	// SealedSeed is the ML-KEM-768 seed of a hardware device, sealed to its
	// P-256 ECDH key (see sealToECDH).
	SealedSeed []byte       `json:"sealed_seed,omitempty"`
	TPM        *TPMKeys     `json:"tpm,omitempty"`
	Enclave    *EnclaveKeys `json:"enclave,omitempty"`
}

// TPMKeys are the TPM blobs of a device's ECDH and signing keys, and the
// Name of the storage primary they were created under.
type TPMKeys struct {
	Parent []byte    `json:"parent"`
	ECDH   TPMObject `json:"ecdh"`
	Sign   TPMObject `json:"sign"`
}

type TPMObject struct {
	Public  []byte `json:"public"`
	Private []byte `json:"private"`
	Name    []byte `json:"name"`
}

// EnclaveKeys are the wrapped private keys of a device's Secure Enclave keys.
type EnclaveKeys struct {
	ECDH       []byte `json:"ecdh"`
	ECDHPublic []byte `json:"ecdh_public"` // uncompressed
	Sign       []byte `json:"sign"`
}

func (md *Metadata) info() PublicInfo {
	id := md.SigningKey.DeviceID()
	return PublicInfo{Backend: md.Backend, Algorithm: md.Algorithm, Recipient: md.Recipient, Device: md.Device,
		DeviceID: string(id), Fingerprint: id.Fingerprint()}
}

// softwareSecret is what a software device keeps in its vault entry.
type softwareSecret struct {
	Age     string `json:"age"`
	Ed25519 string `json:"ed25519"` // hex seed
}

type Diagnosis struct {
	KeyringAvailable  bool   `json:"keyring_available"`
	KeyringReason     string `json:"keyring_reason,omitempty"`
	CredsAvailable    bool   `json:"creds_available"`
	CredsReason       string `json:"creds_reason,omitempty"`
	Backend           string `json:"backend"`
	Device            string `json:"device,omitempty"`
	Available         bool   `json:"available"`
	Reason            string `json:"reason,omitempty"`
	FallbackAvailable bool   `json:"fallback_available"`
	// Fallback is the software backend that would hold a new key.
	Fallback       string `json:"fallback,omitempty"`
	FallbackReason string `json:"fallback_reason,omitempty"`
}

// HardwareBackend keeps a device's two P-256 keys, one for ECDH and one for
// signing, in a TPM or the Secure Enclave.
type HardwareBackend interface {
	Probe() Diagnosis
	// Create makes both keys and records what Load needs in md.
	Create(md *Metadata) (HardwareKey, signing.Signer, error)
	Load(md *Metadata) (HardwareKey, signing.Signer, error)
}

// Vault is where a software device keeps its private keys.
type Vault interface {
	keystore.Backend
	Probe(context.Context) error
}

type Manager struct {
	Dir   string
	Mode  string
	Vault Vault
	// Creds holds software keys where the OS keyring is unavailable: the
	// systemd-creds backend on Linux, nil elsewhere.
	Creds    Vault
	Hardware HardwareBackend
}

func New(c clock.Clock) *Manager {
	m := &Manager{Dir: filepath.Join(config.DataDir(), "identities"), Mode: os.Getenv("ENBU_IDENTITY_BACKEND"),
		Vault: &keystore.KeyringBackend{Clock: c}, Hardware: platformHardware(c)}
	if runtime.GOOS == "linux" {
		m.Creds = &keystore.CredsBackend{Clock: c, Dir: filepath.Join(config.DataDir(), "credentials")}
	}
	return m
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

func softwareBackend(backend string) bool {
	return backend == backendKeyring || backend == backendCreds
}

func (m *Manager) vault(backend string) Vault {
	if backend == backendCreds {
		return m.Creds
	}
	return m.Vault
}

// softwareVault picks where a new software key goes: the OS keyring, or
// systemd-creds when the keyring is unavailable.
func (m *Manager) softwareVault() (string, Vault, error) {
	err := probeVault(context.Background(), m.Vault)
	if err == nil {
		return backendKeyring, m.Vault, nil
	}
	if m.Creds == nil {
		return "", nil, unavailable("OS keyring unavailable", err)
	}
	credsErr := probeVault(context.Background(), m.Creds)
	if credsErr == nil {
		return backendCreds, m.Creds, nil
	}
	return "", nil, unavailable("OS keyring and systemd-creds unavailable", errors.Join(err, credsErr))
}

func softwareName(backend string) string {
	if backend == backendCreds {
		return "systemd-creds"
	}
	return "OS keyring"
}

func probeVault(ctx context.Context, v Vault) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if v == nil {
		return errors.New("not configured")
	}
	return v.Probe(ctx)
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
	if md.Backend == "" || md.Recipient == "" || md.SigningKey.Validate() != nil {
		return nil, errors.New("incomplete identity metadata")
	}
	return &md, nil
}

// Load opens the saved keys of workspaceID and checks them against the
// metadata, so a swapped blob or vault entry cannot change the device's
// recipient or DeviceID.
func (m *Manager) Load(workspaceID string) (*Device, error) {
	mode, err := m.mode()
	if err != nil {
		return nil, err
	}
	md, err := m.read(workspaceID)
	if err != nil {
		return nil, err
	}
	if mode == "hardware" && softwareBackend(md.Backend) || mode == "keyring" && !softwareBackend(md.Backend) {
		return nil, fmt.Errorf("saved identity backend %s does not satisfy %s", md.Backend, mode)
	}
	var d *Device
	if softwareBackend(md.Backend) {
		d, err = m.loadSoftware(md)
	} else {
		d, err = m.loadHardware(md)
	}
	if err != nil {
		return nil, err
	}
	if d.Identity.Recipient().String() != md.Recipient || !d.Signer.Public().Equal(md.SigningKey) {
		_ = d.Close()
		return nil, errors.New("identity key does not match metadata")
	}
	return d, nil
}

func (m *Manager) loadSoftware(md *Metadata) (*Device, error) {
	if md.Algorithm != algSoftware || md.Reference == "" {
		return nil, errors.New("invalid keyring metadata")
	}
	vault := m.vault(md.Backend)
	if vault == nil {
		return nil, unavailable(md.Backend+" unavailable", nil)
	}
	raw, err := vault.Load(vaultService, md.Reference)
	if err != nil {
		return nil, keyringError("loading saved keyring identity", err)
	}
	defer clear(raw)
	var secret softwareSecret
	if err := json.Unmarshal(raw, &secret); err != nil {
		return nil, errors.New("saved keyring identity is malformed")
	}
	key, err := age.ParseHybridIdentity(secret.Age)
	if err != nil {
		return nil, fmt.Errorf("saved keyring identity: %w", err)
	}
	seed, err := hex.DecodeString(secret.Ed25519)
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, errors.New("saved keyring signing key is malformed")
	}
	defer clear(seed)
	return &Device{Identity: FromHybrid(key), Signer: signing.NewEd25519Signer(ed25519.NewKeyFromSeed(seed))}, nil
}

func (m *Manager) loadHardware(md *Metadata) (*Device, error) {
	if m.Hardware == nil {
		return nil, unavailable("saved hardware backend unavailable", nil)
	}
	if md.Algorithm != algHardware {
		return nil, errors.New("invalid hardware identity metadata")
	}
	key, signer, err := m.Hardware.Load(md)
	if err != nil {
		return nil, fmt.Errorf("loading saved hardware identity: %w", err)
	}
	seed, err := openFromECDH(key, md.SealedSeed)
	if err == nil && len(seed) != mlkem.SeedSize {
		err = errors.New("sealed ML-KEM seed has the wrong size")
	}
	var id Identity
	if err == nil {
		id, err = NewHybridHardwareIdentity(key, seed)
	}
	clear(seed)
	if err != nil {
		_ = key.Close()
		_ = signer.Close()
		return nil, fmt.Errorf("loading saved hardware identity: %w", err)
	}
	return &Device{Identity: id, Signer: signer}, nil
}

// Create returns the saved keys of workspaceID, or creates them: in hardware
// when it is available (unless Mode says otherwise), else in software, with a
// warning that says so. Once creation has started, a failure is returned
// rather than silently selecting another backend.
func (m *Manager) Create(workspaceID string) (d *Device, info PublicInfo, warning string, err error) {
	mode, err := m.mode()
	if err != nil {
		return nil, info, "", err
	}
	if err := os.MkdirAll(m.Dir, 0o700); err != nil {
		return nil, info, "", err
	}
	path := m.Path(workspaceID)
	lock, err := acquireCreationLock(path + ".lockfile")
	if err != nil {
		return nil, info, "", fmt.Errorf("identity creation lock (%s): %w", path+".lockfile", err)
	}
	defer func() { _ = lock.Close() }()
	if _, err := os.Stat(path); err == nil {
		d, err := m.Load(workspaceID)
		if err != nil {
			return nil, info, "", err
		}
		md, err := m.read(workspaceID)
		if err != nil {
			_ = d.Close()
			return nil, info, "", err
		}
		return d, md.info(), "", nil
	} else if !errors.Is(err, fs.ErrNotExist) {
		return nil, info, "", err
	}
	var md *Metadata
	if mode != "keyring" {
		probe := Diagnosis{Reason: "hardware backend unavailable"}
		if m.Hardware != nil {
			probe = m.Hardware.Probe()
		}
		if probe.Available {
			if d, md, err = m.createHardware(); err != nil {
				return nil, info, "", err
			}
		} else {
			if mode == "hardware" {
				return nil, info, "", unavailable("hardware identity unavailable: "+probe.Reason, nil)
			}
			warning = "Hardware identity unavailable: " + probe.Reason
		}
	}
	if d == nil {
		if d, md, err = m.createSoftware(); err != nil {
			return nil, info, warning, err
		}
		if warning != "" {
			warning += "; using " + softwareName(md.Backend) + "."
		}
	}
	if err := saveJSON(path, md); err != nil {
		_ = d.Close()
		if md.Reference != "" {
			_ = m.vault(md.Backend).Delete(vaultService, md.Reference)
		}
		return nil, info, warning, err
	}
	info = md.info()
	info.Created = true
	return d, info, warning, nil
}

func (m *Manager) createHardware() (*Device, *Metadata, error) {
	md := &Metadata{Algorithm: algHardware}
	key, signer, err := m.Hardware.Create(md)
	if err != nil {
		return nil, nil, err
	}
	fail := func(err error) (*Device, *Metadata, error) {
		_ = key.Close()
		_ = signer.Close()
		return nil, nil, err
	}
	seed := make([]byte, mlkem.SeedSize)
	defer clear(seed)
	if _, err := rand.Read(seed); err != nil {
		return fail(err)
	}
	if md.SealedSeed, err = sealToECDH(key.PublicKey(), seed); err != nil {
		return fail(err)
	}
	id, err := NewHybridHardwareIdentity(key, seed)
	if err != nil {
		return fail(err)
	}
	md.Recipient, md.SigningKey = id.Recipient().String(), signer.Public()
	return &Device{Identity: id, Signer: signer}, md, nil
}

func (m *Manager) createSoftware() (*Device, *Metadata, error) {
	backend, vault, err := m.softwareVault()
	if err != nil {
		return nil, nil, err
	}
	key, err := age.GenerateHybridIdentity()
	if err != nil {
		return nil, nil, err
	}
	seed := make([]byte, ed25519.SeedSize)
	defer clear(seed)
	if _, err := rand.Read(seed); err != nil {
		return nil, nil, err
	}
	ref := make([]byte, 24)
	if _, err := rand.Read(ref); err != nil {
		return nil, nil, err
	}
	secret, err := json.Marshal(softwareSecret{Age: key.String(), Ed25519: hex.EncodeToString(seed)})
	if err != nil {
		return nil, nil, err
	}
	defer clear(secret)
	md := &Metadata{Backend: backend, Algorithm: algSoftware, Recipient: key.Recipient().String(), Reference: hex.EncodeToString(ref)}
	if err := vault.Store(vaultService, md.Reference, secret); err != nil {
		return nil, nil, keyringError("saving OS keyring identity", err)
	}
	signer := signing.NewEd25519Signer(ed25519.NewKeyFromSeed(seed))
	md.SigningKey = signer.Public()
	return &Device{Identity: FromHybrid(key), Signer: signer}, md, nil
}

// Info checks that the saved keys still open before reporting them.
func (m *Manager) Info(workspaceID string) (PublicInfo, error) {
	d, err := m.Load(workspaceID)
	if err != nil {
		return PublicInfo{}, err
	}
	defer func() { _ = d.Close() }()
	md, err := m.read(workspaceID)
	if err != nil {
		return PublicInfo{}, err
	}
	return md.info(), nil
}

// Doctor probes capabilities and software key storage without creating a
// durable key.
func (m *Manager) Doctor(ctx context.Context) Diagnosis {
	d := Diagnosis{Reason: "hardware backend unavailable"}
	if m.Hardware != nil {
		d = m.Hardware.Probe()
	}
	keyringErr := probeVault(ctx, m.Vault)
	d.KeyringAvailable = keyringErr == nil
	if keyringErr != nil {
		d.KeyringReason = keyringErr.Error()
	}
	credsErr := probeVault(ctx, m.Creds)
	d.CredsAvailable = credsErr == nil
	if credsErr != nil {
		d.CredsReason = credsErr.Error()
	}
	if keyringErr == nil {
		d.FallbackAvailable, d.Fallback = true, backendKeyring
		return d
	}
	d.FallbackReason = "OS keyring unavailable: " + keyringErr.Error()
	if m.Creds == nil {
		return d
	}
	if credsErr != nil {
		d.FallbackReason += "; systemd-creds unavailable: " + credsErr.Error()
	} else {
		d.FallbackAvailable, d.Fallback = true, backendCreds
		d.FallbackReason += "; using systemd-creds"
	}
	return d
}

func saveJSON(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return fsutil.WriteFileAtomic(path, b, 0o600)
}
