package config

import (
	"fmt"
	"sort"
	"strings"
	"uuid"

	"github.com/enbu-net/enbu/pkg/apperr"
)

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
