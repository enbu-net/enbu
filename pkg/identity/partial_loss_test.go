package identity

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"testing"
)

// A missing vault entry differs from deleting metadata: Create must not replace
// an existing device merely because its saved private material cannot load,
// and restoring the entry restores the same keys.
func TestVaultLossPreservesTheDevice(t *testing.T) {
	m := &Manager{Dir: t.TempDir(), Mode: "keyring", Vault: memoryVault{}}
	const ws = "team/workspace"
	d, info, _, err := m.Create(ws)
	if err != nil {
		t.Fatal(err)
	}
	_ = d.Close()
	metadata, err := os.ReadFile(m.Path(ws))
	if err != nil {
		t.Fatal(err)
	}
	md, err := m.read(ws)
	if err != nil {
		t.Fatal(err)
	}
	vault := m.Vault.(memoryVault)
	saved := bytes.Clone(vault[md.Reference])
	delete(vault, md.Reference)
	// Construct a new manager so no process-owned handle can hide the loss.
	m = &Manager{Dir: m.Dir, Mode: "keyring", Vault: vault}
	if _, _, _, err := m.Create(ws); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("Create after material loss = %v", err)
	}
	if len(vault) != 0 {
		t.Fatal("key loss created another vault entry")
	}
	if after, _ := os.ReadFile(m.Path(ws)); !bytes.Equal(after, metadata) {
		t.Fatal("key loss rewrote public identity metadata")
	}
	vault[md.Reference] = saved
	d, restored, _, err := m.Create(ws)
	if err != nil {
		t.Fatal(err)
	}
	_ = d.Close()
	if restored.Created || restored.Recipient != info.Recipient || restored.DeviceID != info.DeviceID {
		t.Fatalf("restoration changed the device: %+v", restored)
	}
}
