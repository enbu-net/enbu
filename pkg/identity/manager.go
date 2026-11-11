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
	// Mode is ENBU_IDENTITY_BACKEND: auto, hardware or keyring.
	Mode             string `json:"mode,omitempty"`
	KeyringAvailable bool   `json:"keyring_available"`
	KeyringReason    string `json:"keyring_reason,omitempty"`
	// KeyringLocked is set when the OS keyring exists but is locked: the
	// person can unlock it, unlike a device without one.
	KeyringLocked bool   `json:"keyring_locked,omitempty"`
	Backend       string `json:"backend"`
	Device        string `json:"device,omitempty"`
	Available     bool   `json:"available"`
	Reason        string `json:"reason,omitempty"`
	// Denied is set when the hardware exists but this user may not use it,
	// such as a TPM outside the tss group. A new key then fails instead of
	// silently going to the OS keyring.
	Denied bool `json:"denied,omitempty"`
	// FallbackAvailable reports that the OS keyring can hold a software key.
	// A new key goes there only when the hardware is absent, not Denied.
	FallbackAvailable bool   `json:"fallback_available"`
	FallbackReason    string `json:"fallback_reason,omitempty"`
	// WSL is set inside WSL, where the Windows enbu.exe keeps the keys and
	// the rest of the diagnosis is the Windows side's.
	WSL *WSLStatus `json:"wsl,omitempty"`
}

// WSLStatus describes the Windows enbu.exe that WSL hands key operations to.
// Error says why it cannot be used: not found, interop disabled, or another
// version.
type WSLStatus struct {
	Exe     string `json:"exe,omitempty"`
	Version string `json:"version,omitempty"`
	Error   string `json:"error,omitempty"`
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
	Dir      string
	Mode     string
	Vault    Vault
	Hardware HardwareBackend
}

func New(c clock.Clock) *Manager {
	return &Manager{Dir: filepath.Join(config.DataDir(), "identities"), Mode: os.Getenv("ENBU_IDENTITY_BACKEND"),
		Vault: &keystore.KeyringBackend{Clock: c}, Hardware: platformHardware(c)}
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

// softwareBackend reports whether backend keeps a software key in the OS
// keyring. It is the only software backend: there is no file fallback.
func softwareBackend(backend string) bool { return backend == backendKeyring }

// vault is where a software backend keeps its keys.
func (m *Manager) vault(string) Vault { return m.Vault }

// softwareVault returns the OS keyring for a new software key, or why it
// cannot take one: missing, or locked until the person unlocks it.
func (m *Manager) softwareVault() (string, Vault, error) {
	if err := probeVault(context.Background(), m.Vault); err != nil {
		return "", nil, keyringUnavailable(err)
	}
	return backendKeyring, m.Vault, nil
}

// keyringUnavailable reports an OS keyring that cannot take a key. A locked
// keyring keeps keystore.ErrLocked in the chain, so the caller can ask the
// person to unlock it.
func keyringUnavailable(err error) error {
	if errors.Is(err, keystore.ErrLocked) {
		return &UnavailableError{Reason: err.Error(), Err: err}
	}
	return unavailable("OS keyring unavailable", err)
}

// softwareName names a software backend in messages.
func softwareName(string) string { return "OS keyring" }

// deniedHardware refuses to replace hardware the user may not use with a
// software key: a permission mistake must not quietly lower the protection.
func deniedHardware(kind, reason string) error {
	return unavailable(kind+" unavailable: "+reason+"; to use a software key in the OS keyring instead, set ENBU_IDENTITY_BACKEND=keyring", nil)
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
		// An identity written by an older enbu keeps its signing key apart and
		// is not migrated: the device starts over with a new identity.
		return nil, unavailable("the identity in "+m.Path(workspaceID)+" was made by an older enbu and cannot be used; remove that file, run enbu init, and ask an admin to approve this device again", nil)
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
			if probe.Denied {
				return nil, info, "", deniedHardware("hardware identity", probe.Reason)
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
	d.Mode, _ = m.mode()
	keyringErr := probeVault(ctx, m.Vault)
	d.KeyringAvailable = keyringErr == nil
	if keyringErr != nil {
		d.KeyringReason = keyringErr.Error()
		d.KeyringLocked = errors.Is(keyringErr, keystore.ErrLocked)
	}
	d.FallbackAvailable = keyringErr == nil
	switch {
	case d.Denied:
		d.FallbackReason = "the hardware exists but this user may not use it, so a new key will not fall back to the OS keyring; set ENBU_IDENTITY_BACKEND=keyring to use it anyway"
	case keyringErr != nil:
		d.FallbackReason = keyringUnavailable(keyringErr).(*UnavailableError).Reason
	}
	return d
}

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
	if err = errors.Join(err, f.Close()); err != nil {
		return err
	}
	return fsutil.Rename(f.Name(), path)
}
