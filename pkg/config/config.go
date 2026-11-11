package config

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"uuid"

	"github.com/BurntSushi/toml"
	"github.com/enbu-net/enbu/pkg/apperr"
	"github.com/enbu-net/enbu/pkg/fsutil"
)

const currentVersion = "v1alpha2"

type StorageConfig struct {
	URL       string `toml:"url" json:"url"`
	Region    string `toml:"region,omitempty" json:"region"`
	Endpoint  string `toml:"endpoint,omitempty" json:"endpoint"`
	PathStyle bool   `toml:"path_style,omitempty" json:"path_style"`
	PlainHTTP bool   `toml:"plain_http,omitempty" json:"plain_http"`
}

type ProjectConfig struct {
	WorkspaceID string `toml:"workspace_id"`
	// ControlGenesis is the trusted digest of the workspace's first signed
	// Control. It is the bootstrap anchor shared through the repository.
	ControlGenesis string        `toml:"control_genesis,omitempty"`
	Storage        StorageConfig `toml:"storage"`
	Version        string        `toml:"version"`
	// DefaultEnv is the team's default environment.
	DefaultEnv   string                       `toml:"default_env,omitempty"`
	Environments map[string]EnvironmentConfig `toml:"env,omitempty"`
	// Current is the environment this user switched to, from the local state.
	// It is personal, so it is never written to enbu.toml.
	Current string `toml:"-"`
}

type EnvironmentConfig struct {
	Output string `toml:"output"`
	// Incarnation names this environment's lineage in storage. Creating an
	// environment draws a new one, so re-creating a deleted name never mixes
	// with the old revisions, and renaming keeps the lineage. An environment
	// written by hand without one is stored under its own name; renaming it
	// records that name here so the lineage stays the same.
	Incarnation string `toml:"incarnation,omitempty"`
}

func LoadProject() (*ProjectConfig, error) {
	return LoadProjectFrom("")
}

func LoadProjectFrom(dir string) (*ProjectConfig, error) {
	path, err := findProjectConfigFrom(dir)
	if err != nil {
		return nil, apperr.Wrap(apperr.CodeConfigNotFound, "enbu.toml not found", err, nil)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading enbu.toml: %w", err)
	}
	return ParseProject(string(data))
}

func ParseProject(content string) (*ProjectConfig, error) {
	var cfg ProjectConfig
	if _, err := toml.Decode(content, &cfg); err != nil {
		return nil, fmt.Errorf("parsing enbu.toml: %w", err)
	}
	if cfg.Version != currentVersion {
		return nil, fmt.Errorf("enbu.toml: unsupported version %q (run 'enbu init' to recreate)", cfg.Version)
	}
	if err := ValidateProjectOutputs(&cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// DecodeProject reads enbu.toml content without checking its version, so the
// values it protects can be compared even in a file enbu would refuse to use.
func DecodeProject(content string) (*ProjectConfig, error) {
	var cfg ProjectConfig
	if _, err := toml.Decode(content, &cfg); err != nil {
		return nil, fmt.Errorf("parsing enbu.toml: %w", err)
	}
	return &cfg, nil
}

func ValidateProjectOutputs(cfg *ProjectConfig) error {
	names := make([]string, 0, len(cfg.Environments))
	for name := range cfg.Environments {
		names = append(names, name)
	}
	sort.Strings(names)
	seen := make(map[string]bool, len(names))
	outputs := make([]string, 0, len(names))
	for _, name := range names {
		if !ValidEnvironmentName(name) || seen[strings.ToLower(name)] {
			return fmt.Errorf("invalid or ambiguous environment name %q", name)
		}
		seen[strings.ToLower(name)] = true
		env := cfg.Environments[name]
		output := strings.TrimSpace(env.Output)
		// Shared configuration must mean the same relative path on every OS.
		// Backslashes, drive prefixes and NTFS alternate streams are not portable.
		if output != env.Output || strings.ContainsAny(output, "\\:") {
			return fmt.Errorf("environment %q output must use a portable relative path", name)
		}
		if output == "" {
			output = DefaultOutput(name)
		}
		clean := filepath.Clean(output)
		// A leading slash is rooted on Windows even without a drive letter,
		// where filepath.IsAbs alone would accept a nonportable configuration.
		if strings.HasPrefix(output, "/") || filepath.IsAbs(output) || clean == "." || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
			return fmt.Errorf("environment %q output must stay within the repository", name)
		}
		for _, previous := range outputs {
			if strings.EqualFold(previous, clean) {
				return fmt.Errorf("environment %q output collides with another environment", name)
			}
		}
		outputs = append(outputs, clean)
	}
	return nil
}

// SaveProjectTo honors an explicit destination. Only an implicit destination
// searches ancestors, so a fresh explicit workspace cannot overwrite a parent.
func SaveProjectTo(dir string, cfg *ProjectConfig) error {
	path := filepath.Join(baseDir(dir), "enbu.toml")
	if dir == "" {
		if found, err := findProjectConfigFrom(""); err == nil {
			path = found
		}
	}

	content, err := MarshalProject(cfg)
	if err != nil {
		return fmt.Errorf("encoding enbu.toml: %w", err)
	}
	// A failed write must leave the shared workspace definition intact. Keep
	// existing regular-file permissions; new configurations remain private.
	mode := os.FileMode(0o600)
	previous, statErr := os.Lstat(path)
	if statErr == nil {
		if previous.Mode().IsRegular() {
			mode = previous.Mode().Perm()
		}
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return statErr
	}
	return fsutil.WriteFileAtomicWith(path, content, mode, fsutil.AtomicOptions{
		Prepare: func(tmp *os.File) error { return preserveProjectOwner(tmp, previous) },
	})
}

// MarshalProject emits the compact, canonical enbu.toml layout. Encoding the
// environment map directly would add a redundant [env] parent table and indent
// every [env.<name>] section.
func MarshalProject(cfg *ProjectConfig) ([]byte, error) {
	var buf bytes.Buffer
	header := struct {
		Version        string `toml:"version"`
		DefaultEnv     string `toml:"default_env,omitempty"`
		WorkspaceID    string `toml:"workspace_id,omitempty"`
		ControlGenesis string `toml:"control_genesis,omitempty"`
	}{Version: cfg.Version, DefaultEnv: cfg.DefaultEnv, WorkspaceID: cfg.WorkspaceID, ControlGenesis: cfg.ControlGenesis}
	if err := toml.NewEncoder(&buf).Encode(header); err != nil {
		return nil, err
	}

	if cfg.Storage.URL != "" {
		buf.WriteString("\n[storage]\n")
		if err := toml.NewEncoder(&buf).Encode(cfg.Storage); err != nil {
			return nil, err
		}
	}
	names := make([]string, 0, len(cfg.Environments))
	for name := range cfg.Environments {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		_, _ = fmt.Fprintf(&buf, "\n[%s]\n", toml.Key{"env", name}.String())
		if err := toml.NewEncoder(&buf).Encode(cfg.Environments[name]); err != nil {
			return nil, err
		}
	}
	return buf.Bytes(), nil
}

func NewProjectWithEnvironment(name string) *ProjectConfig {
	return NewProjectWithIDs(name, func() string { return uuid.NewV4().String() })
}

// NewProjectWithIDs creates a project using an instance-owned identifier source.
func NewProjectWithIDs(name string, newID func() string) *ProjectConfig {
	name = strings.TrimSpace(name)
	if name == "" {
		name = "default"
	}
	envs := map[string]EnvironmentConfig{
		name: {Output: DefaultOutput(name), Incarnation: newID()},
	}
	return &ProjectConfig{
		Version:      currentVersion,
		WorkspaceID:  newID(),
		DefaultEnv:   name,
		Environments: envs,
	}
}

func ProjectConfigPathFrom(dir string) (string, error) {
	return findProjectConfigFrom(dir)
}

func findProjectConfigFrom(dir string) (string, error) {
	dir = baseDir(dir)

	for {
		path := filepath.Join(dir, "enbu.toml")
		if _, err := os.Stat(path); err == nil {
			return path, nil
		}

		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}

	return "", fmt.Errorf("enbu.toml not found (run 'enbu init' first)")
}

func baseDir(dir string) string {
	if dir != "" {
		return dir
	}
	wd, err := os.Getwd()
	if err != nil {
		return "."
	}
	return wd
}
