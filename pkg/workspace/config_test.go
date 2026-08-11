package workspace

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/enbu-net/enbu/pkg/artifact"
	"github.com/enbu-net/enbu/pkg/enrollment"
)

func TestConfigCanonicalRoundTripAndSaveNew(t *testing.T) {
	root := filepath.Join(t.TempDir(), "workspace")
	if err := os.Mkdir(root, 0o755); err != nil {
		t.Fatal(err)
	}
	config := validConfig(t)
	encoded, revision, err := Encode(config)
	if err != nil {
		t.Fatal(err)
	}
	decoded, decodedRevision, err := Decode(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if decodedRevision != revision || decoded.Workspace != config.Workspace {
		t.Fatal("canonical configuration changed")
	}
	savedRevision, err := SaveNew(root, config)
	if err != nil {
		t.Fatal(err)
	}
	if savedRevision != revision {
		t.Fatal("saved revision changed")
	}
	loaded, loadedRevision, err := Load(root)
	if err != nil {
		t.Fatal(err)
	}
	if loadedRevision != revision || loaded.Registry != config.Registry {
		t.Fatal("loaded configuration changed")
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(filepath.Join(root, ConfigFileName))
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("configuration mode = %o", info.Mode().Perm())
		}
	}
	if _, err := SaveNew(root, config); !errors.Is(err, ErrConfigExists) {
		t.Fatalf("second save error = %v", err)
	}
}

func TestConfigRejectsAmbiguousAndUnsafeBindings(t *testing.T) {
	config := validConfig(t)
	duplicate := config.Bindings[0]
	duplicate.ID = mustUUID(t, "33333333-3333-4333-8333-333333333333")
	duplicate.Destination = "SECRETS.env"
	config.Bindings = append(config.Bindings, duplicate)
	if err := config.Validate(); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("case collision error = %v", err)
	}

	config = validConfig(t)
	ancestor := config.Bindings[0]
	ancestor.ID = mustUUID(t, "33333333-3333-4333-8333-333333333333")
	ancestor.Destination = "secrets.env/token"
	config.Bindings = append(config.Bindings, ancestor)
	if err := config.Validate(); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("ancestor collision error = %v", err)
	}

	config = validConfig(t)
	config.Bindings[0].Destination = "../secrets.env"
	if err := config.Validate(); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("unsafe path error = %v", err)
	}

	config = validConfig(t)
	config.Registry = "https://ghcr.io/enbu-net/example"
	if err := config.Validate(); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("registry scheme error = %v", err)
	}
}

func TestLoadRejectsLegacyBeforeMutationAndDoesNotWalkParents(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "workspace")
	if err := os.Mkdir(root, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "enbu.toml"), []byte("legacy"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := SaveNew(root, validConfig(t)); !errors.Is(err, ErrLegacyConfig) {
		t.Fatalf("legacy save error = %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, ConfigFileName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("v1 config unexpectedly exists: %v", err)
	}
	if err := os.Remove(filepath.Join(root, "enbu.toml")); err != nil {
		t.Fatal(err)
	}
	if _, err := SaveNew(parent, validConfig(t)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Load(root); !errors.Is(err, ErrConfigNotFound) {
		t.Fatalf("child load walked to parent: %v", err)
	}
}

func TestLoadRejectsSymlinkedConfigAndWorkspaceComponent(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows reparse-point coverage is in the host capability tests")
	}
	parent := t.TempDir()
	realRoot := filepath.Join(parent, "real")
	if err := os.Mkdir(realRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := SaveNew(realRoot, validConfig(t)); err != nil {
		t.Fatal(err)
	}
	linkedRoot := filepath.Join(parent, "linked")
	if err := os.Symlink(realRoot, linkedRoot); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Load(linkedRoot); !errors.Is(err, ErrUnsafeConfigPath) {
		t.Fatalf("symlinked root error = %v", err)
	}

	other := filepath.Join(parent, "other.cbor")
	if err := os.WriteFile(other, []byte("not a config"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(realRoot, ConfigFileName)); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(other, filepath.Join(realRoot, ConfigFileName)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Load(realRoot); !errors.Is(err, ErrUnsafeConfigPath) {
		t.Fatalf("symlinked config error = %v", err)
	}
}

func TestDecodeRejectsNonCanonicalAndOversizedInput(t *testing.T) {
	encoded, _, err := Encode(validConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := Decode(append(encoded, 0)); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("trailing data error = %v", err)
	}
	if _, _, err := Decode(make([]byte, MaxConfigBytes+1)); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("oversized input error = %v", err)
	}
}

func validConfig(t *testing.T) Config {
	t.Helper()
	materializer, err := artifact.ParseTypeRef("materializers.enbu.net/v1alpha1/DotEnv")
	if err != nil {
		t.Fatal(err)
	}
	authority, err := enrollment.NewAuthority("identity.enbu.example", ed25519.PublicKey(bytes.Repeat([]byte{1}, ed25519.PublicKeySize)))
	if err != nil {
		t.Fatal(err)
	}
	return Config{
		APIVersion:  APIVersion,
		Kind:        KindWorkspace,
		Workspace:   mustUUID(t, "11111111-1111-4111-8111-111111111111"),
		Registry:    "ghcr.io/enbu-net/example-enbu",
		Authorities: []enrollment.Authority{authority},
		Bindings: []Binding{{
			ID:           mustUUID(t, "22222222-2222-4222-8222-222222222222"),
			Target:       mustUUID(t, "44444444-4444-4444-8444-444444444444"),
			Payload:      "content",
			Materializer: materializer,
			Destination:  "secrets.env",
		}},
	}
}

func mustUUID(t *testing.T, value string) artifact.UUID {
	t.Helper()
	parsed, err := artifact.ParseUUID(value)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}
