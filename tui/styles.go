//go:build legacy

package tui

import "charm.land/lipgloss/v2"

var (
	blue      = lipgloss.Color("33")
	blueLight = lipgloss.Color("153")
	muted     = lipgloss.Color("245")

	headerStyle        = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("15"))
	tabStyle           = lipgloss.NewStyle().Foreground(muted)
	activeTabStyle     = lipgloss.NewStyle().Bold(true).Foreground(blueLight).Underline(true)
	sectionStyle       = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("15"))
	tableHeaderStyle   = lipgloss.NewStyle().Bold(true).Foreground(muted)
	selectedStyle      = lipgloss.NewStyle().Foreground(blueLight).Bold(true)
	selectedRowStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("15")).Background(lipgloss.Color("24"))
	dimStyle           = lipgloss.NewStyle().Foreground(muted)
	errorStyle         = lipgloss.NewStyle().Foreground(lipgloss.Color("203"))
	successStyle       = lipgloss.NewStyle().Foreground(lipgloss.Color("78"))
	helpStyle          = lipgloss.NewStyle().Foreground(muted)
	buttonStyle        = lipgloss.NewStyle().Foreground(blueLight).Background(lipgloss.Color("236"))
	buttonPrimaryStyle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("15")).Background(blue)
	codeStyle          = lipgloss.NewStyle().Foreground(lipgloss.Color("252")).Background(lipgloss.Color("235"))
	dialogStyle        = lipgloss.NewStyle().Foreground(lipgloss.Color("60"))
	dialogTitleStyle   = lipgloss.NewStyle().Bold(true).Foreground(blueLight)
)
