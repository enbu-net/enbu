package tui

import (
	"fmt"
	"os"
	"path/filepath"

	tea "charm.land/bubbletea/v2"
	"github.com/enbu-net/enbu/app"
	"github.com/enbu-net/enbu/pkg/config"
)

func Run(a *app.App) error {
	if a == nil {
		return fmt.Errorf("tui: app instance is nil")
	}
	dir, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("tui: determining current directory: %w", err)
	}
	if err := prepareProjectAt(a, dir); err != nil {
		return fmt.Errorf("tui: %w", err)
	}
	m := newModel(a)
	p := tea.NewProgram(m)
	if _, err := p.Run(); err != nil {
		return fmt.Errorf("tui: %w", err)
	}
	return nil
}

func prepareProjectAt(a *app.App, dir string) error {
	path := filepath.Join(dir, "enbu.toml")
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("enbu.toml must exist in the current directory (run 'enbu init' first)")
		}
		return fmt.Errorf("reading %s: %w", path, err)
	}
	cfg, err := config.ParseProject(string(data))
	if err != nil {
		return err
	}
	if err := config.ValidateProjectOutputs(cfg); err != nil {
		return err
	}
	a.SetRepositoryDir(dir)
	return nil
}
