package simulation

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/enbu-net/enbu/pkg/apperr"
	"github.com/enbu-net/enbu/pkg/config"
)

func (w *World) PortableConfig(ctx context.Context) error {
	a := w.Devices[0].App
	for _, name := range []string{"prod", "staging"} {
		if err := a.CreateEnvironment(name); err != nil {
			return err
		}
		if err := a.AddSecret(ctx, name, "TOKEN", name+"-private"); err != nil {
			return err
		}
		w.Model[name] = map[string]string{"TOKEN": name + "-private"}
	}
	rejected := func(run func() error, code apperr.Code) error {
		before, err := a.ReadConfig()
		if err != nil {
			return err
		}
		selection, err := a.CurrentEnvironment()
		if err != nil {
			return err
		}
		start := len(w.Tape.Recording.Entries)
		if err := requireCode(run(), code); err != nil {
			return err
		}
		for _, entry := range w.Tape.Recording.Entries[start:] {
			if entry.Kind == "storage-request" {
				return fmt.Errorf("invalid environment name reached storage")
			}
		}
		after, err := a.ReadConfig()
		if err != nil || after != before {
			return fmt.Errorf("rejected name changed shared config: %v", err)
		}
		current, err := a.CurrentEnvironment()
		if err != nil || current != selection {
			return fmt.Errorf("rejected name changed personal selection: %v", err)
		}
		return nil
	}
	for _, name := range []string{"", ".", "..", "prod.", "../escape", "x/y", `x\y`, "C:prod", "null\x00name", "prod ", "é", "e\u0301", "prоd", "%2fescape", strings.Repeat("a", 101)} {
		for _, run := range []func() error{
			func() error { return a.CreateEnvironment(name) },
			func() error { return a.RenameEnvironment("staging", name) },
			func() error { return a.SwitchEnvironment(name) },
		} {
			if err := rejected(run, apperr.CodeInvalidArgument); err != nil {
				return fmt.Errorf("unsafe name %q: %w", name, err)
			}
		}
	}
	if err := rejected(func() error { return a.CreateEnvironment("PROD") }, apperr.CodeEnvironmentExists); err != nil {
		return err
	}
	if err := rejected(func() error { return a.RenameEnvironment("staging", "PROD") }, apperr.CodeEnvironmentExists); err != nil {
		return err
	}
	cfg, err := config.LoadProjectFrom(a.RepositoryDir)
	if err != nil {
		return err
	}
	lineage := cfg.Resource("prod")
	if err := a.RenameEnvironment("prod", "PROD"); err != nil {
		return err
	}
	w.Model["PROD"] = w.Model["prod"]
	delete(w.Model, "prod")
	cfg, err = config.LoadProjectFrom(a.RepositoryDir)
	if err != nil || cfg.Resource("PROD") != lineage {
		return fmt.Errorf("case-only rename replaced storage lineage: %v", err)
	}
	if err := w.Share(0); err != nil {
		return err
	}
	for i, d := range w.Devices {
		original, err := d.App.ReadConfig()
		if err != nil {
			return err
		}
		cfg, err := config.LoadProjectFrom(d.App.RepositoryDir)
		if err != nil {
			return err
		}
		outside := filepath.Join(w.Root, fmt.Sprintf("outside-%d.env", i))
		local := filepath.Join(d.App.RepositoryDir, ".env")
		preserved := []byte("LOCAL_ONLY=personal\n")
		for _, path := range []string{outside, local} {
			if err := os.WriteFile(path, preserved, 0o600); err != nil {
				return err
			}
		}
		for _, output := range []string{filepath.ToSlash(outside), "../escape.env", `..\escape.env`, "C:/escape.env", ".env:private", " .env ", "dir/../../escape.env"} {
			env := cfg.Environments["default"]
			env.Output = output
			cfg.Environments["default"] = env
			// Bypass the editor: a teammate/attacker directly changes tracked TOML.
			if err := config.SaveProjectTo(d.App.RepositoryDir, cfg); err != nil {
				return err
			}
			for _, run := range []func() error{
				func() error { _, err := d.App.ListSecrets(ctx, "default"); return err },
				func() error { return d.App.PullSecretsToFile(ctx, "default") },
				func() error { return d.App.AddSecret(ctx, "default", "MUST_NOT_PUBLISH", "private") },
				func() error { return d.App.SyncSecrets(ctx, "default") },
				func() error { _, err := d.App.ListHistory(ctx, "default"); return err },
			} {
				start := len(w.Tape.Recording.Entries)
				if err := run(); err == nil {
					return fmt.Errorf("hand-edited unsafe output configuration was accepted")
				}
				for _, entry := range w.Tape.Recording.Entries[start:] {
					if entry.Kind == "storage-request" {
						return fmt.Errorf("unsafe output configuration reached storage")
					}
				}
				for _, path := range []string{outside, local} {
					got, err := os.ReadFile(path)
					if err != nil || string(got) != string(preserved) {
						return fmt.Errorf("unsafe config modified a local file: %v", err)
					}
				}
			}
		}
		if err := os.WriteFile(filepath.Join(d.App.RepositoryDir, "enbu.toml"), []byte(original), 0o644); err != nil {
			return err
		}
		w.Restart(i)
	}
	for _, env := range []string{"default", "PROD", "staging"} {
		if err := w.Check(ctx, env); err != nil {
			return err
		}
	}
	return nil
}
