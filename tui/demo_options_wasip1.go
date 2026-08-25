//go:build wasip1

package tui

import (
	"os"

	tea "charm.land/bubbletea/v2"
)

func demoProgramOptions() []tea.ProgramOption {
	width := demoTerminalDimension(os.Getenv("COLUMNS"), 100)
	height := demoTerminalDimension(os.Getenv("LINES"), 30)
	return []tea.ProgramOption{
		tea.WithInput(os.Stdin),
		tea.WithOutput(os.Stdout),
		tea.WithoutSignalHandler(),
		tea.WithWindowSize(width, height),
	}
}
