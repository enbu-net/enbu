package config

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"uuid"

	"github.com/BurntSushi/toml"
	"github.com/enbu-net/enbu/pkg/apperr"
	"github.com/enbu-net/enbu/pkg/fsutil"
)

const currentVersion = "v1alpha2"

type StorageConfig struct {
	URL       string `toml:"url"`
	Region    string `toml:"region,omitempty"`
	Endpoint  string `toml:"endpoint,omitempty"`
	PathStyle bool   `toml:"path_style,omitempty"`
	PlainHTTP bool   `toml:"plain_http,omitempty"`
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

// LocalConfig is per-user state of one workspace, kept outside the repository.
type LocalConfig struct {
	Current  string `toml:"current,omitempty"`
	Previous string `toml:"previous,omitempty"`
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
	tmp, err := os.CreateTemp(filepath.Dir(path), ".enbu.toml-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if err = preserveProjectOwner(tmp, previous); err == nil {
		err = tmp.Chmod(mode)
	}
	if err == nil {
		if _, err = tmp.Write(content); err == nil {
			err = tmp.Sync()
		}
	}
	if err = errors.Join(err, tmp.Close()); err != nil {
		return err
	}
	return fsutil.Rename(tmp.Name(), path)
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

// LocalStatePath returns the XDG data dir path for per-project local state.
func LocalStatePath(workspaceID string) string {
	return filepath.Join(DataDir(), "state", uuidOrHash(workspaceID)+".toml")
}

// LoadLocalStateFrom reads local state for one explicitly selected device.
func LoadLocalStateFrom(dir, workspaceID string) (*LocalConfig, error) {
	path := filepath.Join(dir, "state", uuidOrHash(workspaceID)+".toml")
	var cfg LocalConfig
	if _, err := toml.DecodeFile(path, &cfg); err != nil {
		if os.IsNotExist(err) {
			return &LocalConfig{}, nil
		}
		return nil, fmt.Errorf("reading local state: %w", err)
	}
	return &cfg, nil
}

// SaveLocalStateTo persists local state for one explicitly selected device.
func SaveLocalStateTo(dir, workspaceID string, cfg *LocalConfig) error {
	path := filepath.Join(dir, "state", uuidOrHash(workspaceID)+".toml")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("creating state directory: %w", err)
	}
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("creating state file: %w", err)
	}
	encoder := toml.NewEncoder(f)
	if err := encoder.Encode(cfg); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
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

// CurrentEnvironment is the environment commands use without --env: the one
// this user switched to while it still exists, else the team default.
func (cfg *ProjectConfig) CurrentEnvironment() string {
	if cfg.Current != "" && (cfg.HasEnvironment(cfg.Current) || (len(cfg.Environments) == 0 && cfg.Current == "default")) {
		return cfg.Current
	}
	if cfg.DefaultEnv != "" {
		return cfg.DefaultEnv
	}
	return "default"
}

func (cfg *ProjectConfig) SetDefault(name string) {
	cfg.DefaultEnv = name
}

func (cfg *ProjectConfig) AddEnvironment(name string) error {
	return cfg.AddEnvironmentWithID(name, func() string { return uuid.NewV4().String() })
}

// AddEnvironmentWithID uses an instance-owned incarnation source.
func (cfg *ProjectConfig) AddEnvironmentWithID(name string, newID func() string) error {
	if !ValidEnvironmentName(name) {
		return apperr.New(apperr.CodeInvalidArgument, fmt.Sprintf("invalid environment name %q", name), apperr.Params{"name": name})
	}
	if cfg.Environments == nil {
		cfg.Environments = make(map[string]EnvironmentConfig)
	}
	if len(cfg.Environments) == 0 && cfg.DefaultEnv == "" {
		// The implicit default is stored under its name; keep it there.
		cfg.Environments["default"] = EnvironmentConfig{Output: DefaultOutput("default")}
		cfg.DefaultEnv = "default"
	}
	if cfg.hasEnvironmentFold(name, "") {
		return apperr.New(apperr.CodeEnvironmentExists, fmt.Sprintf("environment %q already exists", name), apperr.Params{"name": name})
	}
	cfg.Environments[name] = EnvironmentConfig{Output: DefaultOutput(name), Incarnation: newID()}
	return nil
}

func (cfg *ProjectConfig) RemoveEnvironment(name string) error {
	if _, exists := cfg.Environments[name]; !exists {
		return apperr.New(apperr.CodeEnvironmentMissing, fmt.Sprintf("environment %q does not exist", name), apperr.Params{"name": name})
	}
	delete(cfg.Environments, name)
	if cfg.DefaultEnv == name {
		cfg.DefaultEnv = ""
	}
	return nil
}

func (cfg *ProjectConfig) RenameEnvironment(oldName, newName string) error {
	if !ValidEnvironmentName(newName) {
		return apperr.New(apperr.CodeInvalidArgument, fmt.Sprintf("invalid environment name %q", newName), apperr.Params{"name": newName})
	}
	env, exists := cfg.Environments[oldName]
	if !exists {
		return apperr.New(apperr.CodeEnvironmentMissing, fmt.Sprintf("environment %q does not exist", oldName), apperr.Params{"name": oldName})
	}
	if oldName == newName || cfg.hasEnvironmentFold(newName, oldName) {
		return apperr.New(apperr.CodeEnvironmentExists, fmt.Sprintf("environment %q already exists", newName), apperr.Params{"name": newName})
	}
	delete(cfg.Environments, oldName)
	if env.Incarnation == "" {
		// Stored under its old name: keep reading it from there.
		env.Incarnation = oldName
	}
	if env.Output == "" || env.Output == DefaultOutput(oldName) {
		env.Output = DefaultOutput(newName)
	}
	cfg.Environments[newName] = env
	if cfg.DefaultEnv == oldName {
		cfg.DefaultEnv = newName
	}
	return nil
}

// Resource names the storage lineage of an environment's secrets. An
// environment with an incarnation is named by it, so renaming keeps its
// history; one without (an implicit default, or an older enbu.toml) is named by
// its own name.
func (cfg *ProjectConfig) Resource(env string) string {
	if env == "" {
		env = cfg.CurrentEnvironment()
	}
	if inc := cfg.Environments[env].Incarnation; inc != "" {
		return "secrets/" + inc
	}
	return "secrets/" + env
}

func (cfg *ProjectConfig) HasEnvironment(name string) bool {
	_, exists := cfg.Environments[name]
	return exists
}

func (cfg *ProjectConfig) hasEnvironmentFold(name, except string) bool {
	for existing := range cfg.Environments {
		if existing != except && strings.EqualFold(existing, name) {
			return true
		}
	}
	return false
}

func (cfg *ProjectConfig) Environment(name string) (EnvironmentConfig, error) {
	if name == "" {
		name = cfg.CurrentEnvironment()
	}
	if !ValidEnvironmentName(name) {
		return EnvironmentConfig{}, apperr.New(apperr.CodeInvalidArgument, fmt.Sprintf("invalid environment %q", name), apperr.Params{"name": name})
	}
	if len(cfg.Environments) == 0 {
		if name != "default" {
			return EnvironmentConfig{}, apperr.New(apperr.CodeEnvironmentMissing, fmt.Sprintf("environment %q is not defined in enbu.toml", name), apperr.Params{"name": name})
		}
		return EnvironmentConfig{Output: DefaultOutput(name)}, nil
	}
	env, ok := cfg.Environments[name]
	if !ok {
		return EnvironmentConfig{}, apperr.New(apperr.CodeEnvironmentMissing, fmt.Sprintf("environment %q is not defined in enbu.toml", name), apperr.Params{"name": name})
	}
	if env.Output == "" {
		env.Output = DefaultOutput(name)
	}
	return env, nil
}

func (cfg *ProjectConfig) EnvironmentNames() []string {
	if len(cfg.Environments) == 0 {
		return []string{"default"}
	}
	names := make([]string, 0, len(cfg.Environments))
	for name := range cfg.Environments {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func DefaultOutput(name string) string {
	if name == "" || name == "default" {
		return ".env"
	}
	return ".env." + name
}

func ValidEnvironmentName(name string) bool {
	if name == "" || len(name) > 100 || strings.HasSuffix(name, ".") {
		return false
	}
	for _, r := range name {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' || r == '-' || r == '.' {
			continue
		}
		return false
	}
	return true
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

// ParseGitHubRemote returns the owner and repository of a github.com remote
// (git@github.com:owner/repo, https://github.com/owner/repo or
// ssh://git@github.com/owner/repo, each with or without .git). Other hosts are
// an error.
func ParseGitHubRemote(remote string) (string, string, error) {
	var path string
	if rest, ok := strings.CutPrefix(remote, "git@github.com:"); ok {
		path = rest
	} else {
		u, err := url.Parse(remote)
		if err != nil || (u.Scheme != "https" && u.Scheme != "ssh") || u.Hostname() != "github.com" {
			return "", "", errors.New("not a GitHub remote")
		}
		path = u.Path
	}
	path = strings.TrimSuffix(strings.Trim(path, "/"), ".git")
	owner, repo, ok := strings.Cut(path, "/")
	if !ok || owner == "" || repo == "" || strings.Contains(repo, "/") {
		return "", "", errors.New("not a GitHub remote")
	}
	return owner, repo, nil
}

// DataDir is enbu's per-user data directory. It is always absolute: a relative
// path would put identities and checkpoints under the working directory, which
// is usually a Git repository. XDG_DATA_HOME is used only when absolute, as the
// XDG Base Directory specification requires.
func DataDir() string {
	return dataDir(runtime.GOOS, os.Getenv, homeDir)
}

func dataDir(goos string, getenv func(string) string, home func() string) string {
	if xdg := getenv("XDG_DATA_HOME"); filepath.IsAbs(xdg) {
		return filepath.Join(xdg, "enbu")
	}
	switch goos {
	case "darwin":
		return filepath.Join(home(), "Library", "Application Support", "enbu")
	case "windows":
		if local := getenv("LOCALAPPDATA"); filepath.IsAbs(local) {
			return filepath.Join(local, "enbu")
		}
		return filepath.Join(home(), "AppData", "Local", "enbu")
	default:
		return filepath.Join(home(), ".local", "share", "enbu")
	}
}

// unresolvedHome stands in for a home directory that cannot be found. It is
// absolute, so nothing lands in the working directory, and it does not exist,
// so reads find nothing and writes fail instead of going somewhere unexpected.
// On Windows it sits on the drive of the temporary directory, because a path
// without a drive letter is not absolute there.
var unresolvedHome = filepath.VolumeName(os.TempDir()) + string(filepath.Separator) + "nonexistent"

// homeDir is the user's home directory: $HOME (or %USERPROFILE%) when it is
// absolute, otherwise the home directory in the user database, which cron jobs,
// some services and `env -i` still have when HOME is unset.
func homeDir() string {
	if home, err := os.UserHomeDir(); err == nil && filepath.IsAbs(home) {
		return home
	}
	if u, err := user.Current(); err == nil && filepath.IsAbs(u.HomeDir) {
		return u.HomeDir
	}
	return unresolvedHome
}

func uuidOrHash(id string) string { return fmt.Sprintf("%x", sha256.Sum256([]byte(id))) }
