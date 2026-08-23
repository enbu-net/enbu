//go:build wasip1

package tui

import (
	"os"

	tea "charm.land/bubbletea/v2"
)

func demoProgramOptions() []tea.ProgramOption {
	return []tea.ProgramOption{
		tea.WithInput(os.Stdin),
		tea.WithOutput(os.Stdout),
		tea.WithoutSignalHandler(),
	}
}
