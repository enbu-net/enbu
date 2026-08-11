// Package workspace defines the shared, non-secret workspace configuration
// used by the v1 application host. It deliberately does not understand the
// legacy enbu.toml format.
package workspace

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/enbu-net/enbu/pkg/artifact"
	"github.com/enbu-net/enbu/pkg/enrollment"
	"github.com/enbu-net/enbu/pkg/host"
	"github.com/enbu-net/enbu/pkg/schema"
	"github.com/opencontainers/go-digest"
	"oras.land/oras-go/v2/registry/remote"
)

const (
	APIVersion        = "config.enbu.net/v1alpha1"
	KindWorkspace     = "Workspace"
	ConfigFileName    = "enbu.workspace.cbor"
	MaxConfigBytes    = 1024 * 1024
	MaxConfigBindings = 1024
)

var (
	ErrConfigNotFound   = errors.New("workspace: configuration not found")
	ErrInvalidConfig    = errors.New("workspace: invalid configuration")
	ErrLegacyConfig     = errors.New("workspace: unsupported legacy configuration")
	ErrConfigExists     = errors.New("workspace: configuration already exists")
	ErrUnsafeConfigPath = errors.New("workspace: unsafe configuration path")
)

// Config is shared repository state. It contains no credentials, absolute
// paths, selected device, or mutable head pointer.
type Config struct {
	APIVersion  string                 `cbor:"apiVersion"`
	Kind        string                 `cbor:"kind"`
	Workspace   artifact.UUID          `cbor:"workspace"`
	Registry    string                 `cbor:"registry"`
	Authorities []enrollment.Authority `cbor:"authorities"`
	Bindings    []Binding              `cbor:"bindings,omitempty"`
}

// Binding describes a repository-relative materialization. Destination uses
// the portable FileTree path grammar on every operating system.
type Binding struct {
	ID           artifact.UUID    `cbor:"id"`
	Target       artifact.UUID    `cbor:"target"`
	Payload      string           `cbor:"payload"`
	Materializer artifact.TypeRef `cbor:"materializer"`
	Destination  string           `cbor:"destination"`
}

func (config Config) Validate() error {
	if config.APIVersion != APIVersion || config.Kind != KindWorkspace {
		return fmt.Errorf("%w: unsupported type", ErrInvalidConfig)
	}
	if err := config.Workspace.Validate(); err != nil {
		return fmt.Errorf("%w: workspace ID: %v", ErrInvalidConfig, err)
	}
	if err := validateRegistry(config.Registry); err != nil {
		return fmt.Errorf("%w: registry: %v", ErrInvalidConfig, err)
	}
	if _, err := enrollment.NewVerifier(config.Authorities); err != nil {
		return fmt.Errorf("%w: enrollment authorities: %v", ErrInvalidConfig, err)
	}
	if len(config.Bindings) > MaxConfigBindings {
		return fmt.Errorf("%w: binding count exceeds %d", ErrInvalidConfig, MaxConfigBindings)
	}
	seenIDs := make(map[artifact.UUID]struct{}, len(config.Bindings))
	destinations := make([]string, 0, len(config.Bindings))
	for index, binding := range config.Bindings {
		if err := binding.Validate(); err != nil {
			return fmt.Errorf("%w: bindings[%d]: %v", ErrInvalidConfig, index, err)
		}
		if _, exists := seenIDs[binding.ID]; exists {
			return fmt.Errorf("%w: duplicate binding ID", ErrInvalidConfig)
		}
		seenIDs[binding.ID] = struct{}{}
		destinations = append(destinations, binding.Destination)
	}
	if err := schema.ValidateFileTreePaths(destinations); err != nil {
		return fmt.Errorf("%w: binding destinations: %v", ErrInvalidConfig, err)
	}
	return nil
}

func (binding Binding) Validate() error {
	if err := binding.ID.Validate(); err != nil {
		return fmt.Errorf("binding ID: %v", err)
	}
	if err := binding.Target.Validate(); err != nil {
		return fmt.Errorf("target UID: %v", err)
	}
	if err := validatePayloadName(binding.Payload); err != nil {
		return err
	}
	if err := binding.Materializer.Validate(); err != nil {
		return fmt.Errorf("materializer: %v", err)
	}
	if err := schema.ValidateFileTreePath(binding.Destination); err != nil {
		return fmt.Errorf("destination: %v", err)
	}
	return nil
}

func validatePayloadName(value string) error {
	if value == "" || len(value) > 253 || strings.ContainsAny(value, "/\\\x00") {
		return errors.New("payload name must be a portable non-empty name of at most 253 bytes")
	}
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return errors.New("payload name must not contain control characters")
		}
	}
	return nil
}

func validateRegistry(value string) error {
	if value == "" || value != strings.ToLower(value) || strings.Contains(value, "://") || strings.Contains(value, "@") || strings.ContainsRune(value, 0) {
		return errors.New("must be a lowercase OCI repository without scheme, credentials, tag, or digest")
	}
	repository, err := remote.NewRepository(value)
	if err != nil {
		return err
	}
	if repository.Reference.Reference != "" {
		return errors.New("must not contain a tag or digest")
	}
	return nil
}

// Encode returns the canonical bytes and their configuration revision.
func Encode(config Config) ([]byte, digest.Digest, error) {
	if err := config.Validate(); err != nil {
		return nil, "", err
	}
	encoded, err := artifact.MarshalCanonical(config)
	if err != nil {
		return nil, "", fmt.Errorf("%w: encode: %v", ErrInvalidConfig, err)
	}
	if len(encoded) > MaxConfigBytes {
		return nil, "", fmt.Errorf("%w: encoded configuration exceeds %d bytes", ErrInvalidConfig, MaxConfigBytes)
	}
	return encoded, digest.FromBytes(encoded), nil
}

// Decode accepts only the exact canonical representation.
func Decode(encoded []byte) (Config, digest.Digest, error) {
	if len(encoded) == 0 || len(encoded) > MaxConfigBytes {
		return Config{}, "", fmt.Errorf("%w: encoded configuration size", ErrInvalidConfig)
	}
	var config Config
	if err := artifact.UnmarshalStrict(encoded, &config); err != nil {
		return Config{}, "", fmt.Errorf("%w: decode: %v", ErrInvalidConfig, err)
	}
	canonical, revision, err := Encode(config)
	if err != nil {
		return Config{}, "", err
	}
	if !bytes.Equal(encoded, canonical) {
		return Config{}, "", fmt.Errorf("%w: non-canonical encoding", ErrInvalidConfig)
	}
	return config, revision, nil
}

func ConfigPath(root string) (string, error) {
	if root == "" || !filepath.IsAbs(root) || filepath.Clean(root) != root || strings.ContainsRune(root, 0) {
		return "", ErrUnsafeConfigPath
	}
	return filepath.Join(root, ConfigFileName), nil
}

// Load reads only the explicitly selected workspace root. It never walks to a
// parent directory and rejects legacy configuration before opening v1 state.
func Load(root string) (Config, digest.Digest, error) {
	path, err := ConfigPath(root)
	if err != nil {
		return Config{}, "", err
	}
	if legacy, err := legacyConfiguration(root); err != nil {
		return Config{}, "", err
	} else if legacy != "" {
		return Config{}, "", fmt.Errorf("%w: %s", ErrLegacyConfig, legacy)
	}
	input, err := host.NewFileInput(path)
	if err != nil {
		return Config{}, "", fmt.Errorf("%w: %v", ErrUnsafeConfigPath, err)
	}
	file, err := input.Open(context.Background())
	if errors.Is(err, os.ErrNotExist) {
		return Config{}, "", ErrConfigNotFound
	}
	if err != nil {
		return Config{}, "", fmt.Errorf("%w: open: %v", ErrUnsafeConfigPath, err)
	}
	encoded, readErr := io.ReadAll(io.LimitReader(file, MaxConfigBytes+1))
	closeErr := file.Close()
	if readErr != nil {
		return Config{}, "", fmt.Errorf("read workspace configuration: %w", readErr)
	}
	if closeErr != nil {
		return Config{}, "", fmt.Errorf("close workspace configuration: %w", closeErr)
	}
	if len(encoded) == 0 || len(encoded) > MaxConfigBytes {
		return Config{}, "", ErrUnsafeConfigPath
	}
	return Decode(encoded)
}

// SaveNew creates a v1 configuration exactly once. Replacing a legacy or
// existing configuration requires a separate, explicitly destructive flow.
func SaveNew(root string, config Config) (digest.Digest, error) {
	path, err := ConfigPath(root)
	if err != nil {
		return "", err
	}
	if legacy, err := legacyConfiguration(root); err != nil {
		return "", err
	} else if legacy != "" {
		return "", fmt.Errorf("%w: %s", ErrLegacyConfig, legacy)
	}
	encoded, revision, err := Encode(config)
	if err != nil {
		return "", err
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, os.ErrExist) {
		return "", ErrConfigExists
	}
	if err != nil {
		return "", fmt.Errorf("create workspace configuration: %w", err)
	}
	remove := true
	defer func() {
		_ = file.Close()
		if remove {
			_ = os.Remove(path)
		}
	}()
	if _, err := file.Write(encoded); err != nil {
		return "", fmt.Errorf("write workspace configuration: %w", err)
	}
	if err := file.Sync(); err != nil {
		return "", fmt.Errorf("sync workspace configuration: %w", err)
	}
	if err := file.Close(); err != nil {
		return "", fmt.Errorf("close workspace configuration: %w", err)
	}
	remove = false
	return revision, nil
}

func legacyConfiguration(root string) (string, error) {
	for _, name := range []string{"enbu.toml", ".enbu.local"} {
		_, err := os.Lstat(filepath.Join(root, name))
		switch {
		case err == nil:
			return name, nil
		case errors.Is(err, os.ErrNotExist):
			continue
		default:
			return "", fmt.Errorf("inspect legacy configuration %s: %w", name, err)
		}
	}
	return "", nil
}
