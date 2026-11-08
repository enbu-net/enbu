package identity

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"reflect"
	"testing"
)

// A missing vault entry differs from deleting metadata: Create must not replace
// an existing identity merely because its saved private material cannot load.
func TestPartialVaultLossPreservesIdentityBindings(t *testing.T) {
	for _, slot := range []string{"current", "signing", "next", "previous"} {
		t.Run(slot, func(t *testing.T) {
			m := &Manager{Dir: t.TempDir(), Mode: "keyring", Vault: memoryVault{}}
			const ws = "team/workspace"
			id, _, _, err := m.Create(ws)
			if err != nil {
				t.Fatal(err)
			}
			_ = id.Close()
			signer, signingInfo, _, err := m.CreateSigner(ws)
			if err != nil {
				t.Fatal(err)
			}
			_ = signer.Close()
			pending, _, _, err := m.CreatePending(ws)
			if err != nil {
				t.Fatal(err)
			}
			_ = pending.Close()
			if err := m.PromotePending(ws); err != nil {
				t.Fatal(err)
			}
			pending, _, _, err = m.CreatePending(ws)
			if err != nil {
				t.Fatal(err)
			}
			_ = pending.Close()
			paths := []string{m.Path(ws), m.SignerPath(ws), m.slotPath(ws, "next"), m.slotPath(ws, "previous")}
			metadata := map[string][]byte{}
			for _, path := range paths {
				b, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				metadata[path] = b
			}
			var ref string
			if slot == "signing" {
				md, err := m.readSigner(ws)
				if err != nil {
					t.Fatal(err)
				}
				ref = md.Reference
			} else {
				path := m.Path(ws)
				if slot != "current" {
					path = m.slotPath(ws, slot)
				}
				md, err := m.readPath(path)
				if err != nil {
					t.Fatal(err)
				}
				ref = md.Reference
			}
			vault := m.Vault.(memoryVault)
			saved := bytes.Clone(vault[ref])
			if len(saved) == 0 {
				t.Fatal("fixture has no private material to lose")
			}
			delete(vault, ref)
			remaining := memoryVault{}
			for key, value := range vault {
				remaining[key] = bytes.Clone(value)
			}
			// Construct a new manager so no process-owned handle can hide the loss.
			m = &Manager{Dir: m.Dir, Mode: "keyring", Vault: vault}
			switch slot {
			case "current":
				if _, _, _, err := m.Create(ws); !errors.Is(err, fs.ErrNotExist) {
					t.Fatalf("Create after material loss = %v", err)
				}
			case "signing":
				if _, _, _, err := m.CreateSigner(ws); !errors.Is(err, fs.ErrNotExist) {
					t.Fatalf("CreateSigner after material loss = %v", err)
				}
			case "next":
				if _, _, _, err := m.CreatePending(ws); !errors.Is(err, fs.ErrNotExist) {
					t.Fatalf("CreatePending after material loss = %v", err)
				}
			case "previous":
				ids, err := m.LoadRetained(ws)
				if err != nil {
					t.Fatal(err)
				}
				for _, id := range ids {
					_ = id.Close()
				}
				if len(ids) != 1 {
					t.Fatalf("retained identities = %d, want only intact pending key", len(ids))
				}
			}
			if !reflect.DeepEqual(vault, remaining) {
				t.Fatal("key loss modified another vault entry")
			}
			for path, before := range metadata {
				after, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(before, after) {
					t.Fatal("key loss rewrote public identity metadata")
				}
			}
			// Restoring only the lost entry must restore the original identities,
			// without regeneration, recipient changes, or signing-ID replacement.
			vault[ref] = saved
			current, info, _, err := m.Create(ws)
			if err != nil {
				t.Fatal(err)
			}
			_ = current.Close()
			if info.Created {
				t.Fatal("restoration regenerated encryption identity")
			}
			restored, infoSigner, _, err := m.CreateSigner(ws)
			if err != nil {
				t.Fatal(err)
			}
			_ = restored.Close()
			if infoSigner.Created || infoSigner.DeviceID != signingInfo.DeviceID {
				t.Fatal("restoration replaced the signing identity")
			}
			ids, err := m.LoadRetained(ws)
			if err != nil {
				t.Fatal(err)
			}
			for _, id := range ids {
				_ = id.Close()
			}
			if len(ids) != 2 {
				t.Fatalf("restored retained identities = %d, want pending and previous", len(ids))
			}
		})
	}
}
