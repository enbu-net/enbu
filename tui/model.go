package tui

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"charm.land/bubbles/v2/key"
	"charm.land/bubbles/v2/spinner"
	"charm.land/bubbles/v2/textarea"
	"charm.land/bubbles/v2/textinput"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"github.com/enbu-net/enbu/app"
	"github.com/enbu-net/enbu/pkg/config"
)

type tabState int

const (
	tabSecrets tabState = iota
	tabMembers
	tabSettings
)

type overlayState int

const (
	overlayNone overlayState = iota
	overlayAdd
	overlayEdit
	overlayDelete
	overlayCreateEnvironment
)

type hitKind int

const (
	hitTab hitKind = iota
	hitEnvironment
	hitEnvironmentOption
	hitCreateEnvironment
	hitPull
	hitSecretRow
	hitEdit
	hitReveal
	hitCopyKey
	hitCopyValue
	hitDelete
	hitAdd
	hitRefreshMembers
	hitSettingsView
	hitSettingsEdit
	hitInputKey
	hitInputValue
	hitConfirm
	hitCancel
)

type hitRegion struct {
	kind       hitKind
	x, y, w, h int
	index      int
	value      string
}

func (h hitRegion) contains(x, y int) bool {
	return x >= h.x && x < h.x+h.w && y >= h.y && y < h.y+h.h
}

type model struct {
	app         *app.App
	tab         tabState
	overlay     overlayState
	secrets     []secretEntry
	cursor      int
	offset      int
	envs        []envItem
	current     string
	repository  string
	envMenuOpen bool
	envCursor   int

	recipients []app.RecipientInfo

	configContent string
	configDraft   string
	configCode    bool
	configEditing bool
	configInput   textarea.Model

	keyInput   textinput.Model
	valueInput textinput.Model
	envInput   textinput.Model
	focusKey   bool

	revealed map[string]bool

	spinner         spinner.Model
	animateSpinner  bool
	copyToClipboard func(string) error

	loading bool
	err     error
	status  string

	width  int
	height int
	hits   []hitRegion
}

type secretEntry struct {
	key   string
	value string
}

func newModel(a *app.App) *model {
	sp := spinner.New()
	sp.Spinner = spinner.Dot

	ki := textinput.New()
	ki.Placeholder = "KEY"
	ki.CharLimit = 256
	ki.SetWidth(28)

	vi := textinput.New()
	vi.Placeholder = "VALUE"
	vi.CharLimit = 4096
	vi.SetWidth(38)

	ei := textinput.New()
	ei.Placeholder = "environment-name"
	ei.CharLimit = 100
	ei.SetWidth(32)

	ci := textarea.New()
	ci.Placeholder = "enbu.toml"
	ci.CharLimit = 65536
	ci.SetWidth(72)
	ci.SetHeight(14)
	ci.ShowLineNumbers = true

	return &model{
		app:             a,
		tab:             tabSecrets,
		spinner:         sp,
		animateSpinner:  true,
		keyInput:        ki,
		valueInput:      vi,
		envInput:        ei,
		configInput:     ci,
		focusKey:        true,
		loading:         true,
		revealed:        make(map[string]bool),
		copyToClipboard: copyToClipboard,
	}
}

func (m *model) Init() tea.Cmd {
	if !m.animateSpinner {
		return m.loadWorkspace()
	}
	return tea.Batch(m.spinner.Tick, m.loadWorkspace())
}

func (m *model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.resizeInputs()
		return m, nil
	case spinner.TickMsg:
		if !m.animateSpinner {
			return m, nil
		}
		var cmd tea.Cmd
		m.spinner, cmd = m.spinner.Update(msg)
		return m, cmd
	case workspaceLoadedMsg:
		m.loading = false
		m.secrets = mapToEntries(msg.secrets)
		m.envs = msg.envs
		m.current = msg.current
		m.repository = msg.repository
		m.revealed = make(map[string]bool)
		m.err = nil
		m.clampCursor()
		return m, nil
	case recipientsLoadedMsg:
		m.loading = false
		m.recipients = msg.recipients
		m.err = nil
		return m, nil
	case configLoadedMsg:
		m.loading = false
		m.configContent = msg.content
		m.configDraft = msg.content
		m.configEditing = false
		m.err = nil
		return m, nil
	case configSavedMsg:
		m.loading = true
		m.configContent = m.configDraft
		m.configEditing = false
		m.status = "Saved enbu.toml"
		m.err = nil
		m.revealed = make(map[string]bool)
		return m, m.loadWorkspace()
	case operationDoneMsg:
		m.status = msg.message
		m.err = nil
		m.overlay = overlayNone
		m.loading = true
		m.revealed = make(map[string]bool)
		return m, m.loadWorkspace()
	case clipboardDoneMsg:
		m.status = msg.message
		m.err = nil
		return m, nil
	case errMsg:
		m.loading = false
		m.err = msg.err
		return m, nil
	case tea.MouseMsg:
		if m.loading {
			return m, nil
		}
		return m.handleMouse(msg)
	case tea.KeyPressMsg:
		if m.loading {
			if key.Matches(msg, keys.Quit) {
				return m, tea.Quit
			}
			return m, nil
		}
		return m.handleKey(msg)
	}

	if m.configEditing {
		var cmd tea.Cmd
		m.configInput, cmd = m.configInput.Update(msg)
		return m, cmd
	}
	if m.overlay == overlayAdd || m.overlay == overlayEdit || m.overlay == overlayCreateEnvironment {
		return m.updateInputs(msg)
	}
	return m, nil
}

func (m *model) resizeInputs() {
	inputWidth := max(18, min(48, m.width-22))
	m.keyInput.SetWidth(inputWidth)
	m.valueInput.SetWidth(inputWidth)
	m.envInput.SetWidth(inputWidth)
	m.configInput.SetWidth(max(30, m.width-10))
	m.configInput.SetHeight(max(6, m.height-13))
}

func (m *model) handleKey(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	if m.overlay != overlayNone {
		return m.handleOverlayKey(msg)
	}
	if m.configEditing {
		return m.handleConfigEditorKey(msg)
	}
	if key.Matches(msg, keys.Quit) {
		return m, tea.Quit
	}
	if key.Matches(msg, keys.TabNext) {
		return m.activateTab(tabState((int(m.tab) + 1) % 3))
	}
	if key.Matches(msg, keys.TabPrev) {
		return m.activateTab(tabState((int(m.tab) + 2) % 3))
	}
	if key.Matches(msg, keys.SecretsTab) {
		return m.activateTab(tabSecrets)
	}
	if key.Matches(msg, keys.MembersTab) {
		return m.activateTab(tabMembers)
	}
	if key.Matches(msg, keys.SettingsTab) {
		return m.activateTab(tabSettings)
	}

	switch m.tab {
	case tabSecrets:
		return m.handleSecretsKey(msg)
	case tabMembers:
		if key.Matches(msg, keys.Refresh) {
			m.loading = true
			return m, m.loadRecipients()
		}
	case tabSettings:
		switch {
		case key.Matches(msg, keys.Edit):
			return m.startConfigEdit()
		case key.Matches(msg, keys.ToggleView):
			m.configCode = !m.configCode
		}
	}
	return m, nil
}

func (m *model) handleSecretsKey(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	if m.environmentOpen() {
		switch {
		case key.Matches(msg, keys.Escape):
			m.status = ""
			m.closeEnvironment()
		case key.Matches(msg, keys.Up):
			m.envCursor = max(0, m.envCursor-1)
		case key.Matches(msg, keys.Down):
			m.envCursor = min(len(m.envs), m.envCursor+1)
		case key.Matches(msg, keys.Enter):
			if m.envCursor == len(m.envs) {
				m.closeEnvironment()
				m.openCreateEnvironment()
			} else if len(m.envs) > 0 {
				return m.selectEnvironment(m.envs[m.envCursor].name)
			}
		}
		return m, nil
	}

	switch {
	case key.Matches(msg, keys.Up):
		m.cursor = max(0, m.cursor-1)
		m.ensureCursorVisible()
	case key.Matches(msg, keys.Down):
		m.cursor = min(max(0, len(m.secrets)-1), m.cursor+1)
		m.ensureCursorVisible()
	case key.Matches(msg, keys.Add):
		m.openAdd()
	case key.Matches(msg, keys.Edit):
		m.openEdit()
	case key.Matches(msg, keys.Delete):
		m.openDelete()
	case key.Matches(msg, keys.Switch):
		m.openEnvironment()
	case key.Matches(msg, keys.Refresh):
		m.loading = true
		return m, m.loadWorkspace()
	case key.Matches(msg, keys.Pull):
		m.loading = true
		return m, m.pullSecrets()
	case key.Matches(msg, keys.Reveal):
		m.toggleReveal(m.cursor)
	case key.Matches(msg, keys.CopyValue):
		return m.copySecret(m.cursor, false)
	case key.Matches(msg, keys.CopyKey):
		return m.copySecret(m.cursor, true)
	}
	return m, nil
}

func (m *model) handleOverlayKey(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	if key.Matches(msg, keys.Escape) {
		m.closeOverlay()
		return m, nil
	}
	if m.overlay == overlayDelete {
		if key.Matches(msg, keys.Enter) && len(m.secrets) > 0 {
			m.loading = true
			return m, m.deleteSecret(m.secrets[m.cursor].key)
		}
		return m, nil
	}
	if key.Matches(msg, keys.Tab) {
		if m.overlay == overlayAdd {
			m.focusKey = !m.focusKey
			m.focusSecretInput()
		}
		return m, nil
	}
	if key.Matches(msg, keys.Enter) {
		if m.overlay == overlayAdd && m.focusKey {
			if strings.TrimSpace(m.keyInput.Value()) == "" {
				m.err = fmt.Errorf("key cannot be empty")
				return m, nil
			}
			m.focusKey = false
			m.focusSecretInput()
			m.err = nil
			return m, nil
		}
		return m.confirmOverlay()
	}
	return m.updateInputs(msg)
}

func (m *model) handleConfigEditorKey(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	switch {
	case key.Matches(msg, keys.Escape):
		m.configEditing = false
		m.configDraft = m.configContent
		m.configInput.Blur()
		m.err = nil
		return m, nil
	case key.Matches(msg, keys.Save):
		m.configDraft = m.configInput.Value()
		cfg, err := config.ParseProject(m.configDraft)
		if err != nil {
			m.err = err
			return m, nil
		}
		if err := config.ValidateProjectOutputs(cfg); err != nil {
			m.err = err
			return m, nil
		}
		m.loading = true
		return m, m.saveConfig(m.configDraft)
	}
	var cmd tea.Cmd
	m.configInput, cmd = m.configInput.Update(msg)
	return m, cmd
}

func (m *model) updateInputs(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmds []tea.Cmd
	var cmd tea.Cmd
	m.keyInput, cmd = m.keyInput.Update(msg)
	cmds = append(cmds, cmd)
	m.valueInput, cmd = m.valueInput.Update(msg)
	cmds = append(cmds, cmd)
	m.envInput, cmd = m.envInput.Update(msg)
	cmds = append(cmds, cmd)
	return m, tea.Batch(cmds...)
}

func (m *model) handleMouse(msg tea.MouseMsg) (tea.Model, tea.Cmd) {
	mouse := msg.Mouse()
	if _, ok := msg.(tea.MouseWheelMsg); ok {
		if m.tab == tabSecrets && m.overlay == overlayNone {
			delta := 3
			if mouse.Button == tea.MouseWheelUp {
				delta = -3
			}
			m.offset = max(0, min(m.maxOffset(), m.offset+delta))
			m.cursor = max(m.offset, min(len(m.secrets)-1, m.offset))
		}
		return m, nil
	}
	if _, ok := msg.(tea.MouseMotionMsg); ok {
		for _, hit := range m.hits {
			if hit.kind == hitSecretRow && hit.contains(mouse.X, mouse.Y) {
				m.cursor = hit.index
				break
			}
		}
		return m, nil
	}
	if _, ok := msg.(tea.MouseClickMsg); !ok || mouse.Button != tea.MouseLeft {
		return m, nil
	}
	for i := len(m.hits) - 1; i >= 0; i-- {
		hit := m.hits[i]
		if !hit.contains(mouse.X, mouse.Y) {
			continue
		}
		switch hit.kind {
		case hitTab:
			return m.activateTab(tabState(hit.index))
		case hitEnvironment:
			m.openEnvironment()
		case hitEnvironmentOption:
			return m.selectEnvironment(hit.value)
		case hitCreateEnvironment:
			m.closeEnvironment()
			m.openCreateEnvironment()
		case hitPull:
			m.loading = true
			return m, m.pullSecrets()
		case hitSecretRow:
			m.cursor = hit.index
		case hitEdit:
			m.cursor = hit.index
			m.openEdit()
		case hitReveal:
			m.toggleReveal(hit.index)
		case hitCopyKey:
			return m.copySecret(hit.index, true)
		case hitCopyValue:
			return m.copySecret(hit.index, false)
		case hitDelete:
			m.cursor = hit.index
			m.openDelete()
		case hitAdd:
			m.openAdd()
		case hitRefreshMembers:
			m.loading = true
			return m, m.loadRecipients()
		case hitSettingsView:
			m.configCode = !m.configCode
		case hitSettingsEdit:
			return m.startConfigEdit()
		case hitInputKey:
			m.focusKey = true
			m.focusSecretInput()
		case hitInputValue:
			m.focusKey = false
			m.focusSecretInput()
		case hitConfirm:
			if m.configEditing {
				m.configDraft = m.configInput.Value()
				cfg, err := config.ParseProject(m.configDraft)
				if err != nil {
					m.err = err
					return m, nil
				}
				if err := config.ValidateProjectOutputs(cfg); err != nil {
					m.err = err
					return m, nil
				}
				m.loading = true
				return m, m.saveConfig(m.configDraft)
			}
			return m.confirmOverlay()
		case hitCancel:
			if m.configEditing {
				m.configEditing = false
				m.configDraft = m.configContent
				m.configInput.Blur()
				m.err = nil
			} else {
				m.closeOverlay()
			}
		}
		break
	}
	return m, nil
}

func (m *model) activateTab(tab tabState) (tea.Model, tea.Cmd) {
	if m.tab == tab && ((tab == tabMembers && m.recipients != nil) || (tab == tabSettings && m.configContent != "") || tab == tabSecrets) {
		return m, nil
	}
	if m.configEditing && tab != tabSettings {
		m.configEditing = false
		m.configDraft = m.configContent
		m.configInput.Blur()
	}
	m.tab = tab
	m.overlay = overlayNone
	m.envMenuOpen = false
	m.err = nil
	m.status = ""
	switch tab {
	case tabMembers:
		m.loading = true
		return m, m.loadRecipients()
	case tabSettings:
		m.loading = true
		return m, m.loadConfig()
	default:
		return m, nil
	}
}

func (m *model) View() tea.View {
	m.hits = m.hits[:0]
	if m.width > 0 && m.width < 58 || m.height > 0 && m.height < 16 {
		return terminalView(errorStyle.Render("enbu needs a terminal of at least 58×16"))
	}

	lines := []string{headerStyle.Render("💃 enbu")}
	if m.repository != "" {
		lines[0] += "  " + dimStyle.Render(m.repository)
	}
	lines = append(lines, "")
	lines = append(lines, m.renderTabs(2), "")
	if m.err != nil {
		lines = append(lines, errorStyle.Render("! "+m.err.Error()))
	} else if m.status != "" {
		lines = append(lines, successStyle.Render("✓ "+m.status))
	} else {
		lines = append(lines, "")
	}
	if m.loading {
		lines = append(lines, "", "  "+m.spinner.View()+" Loading…")
		return terminalView(strings.Join(lines, "\n"))
	}

	switch m.tab {
	case tabSecrets:
		lines = append(lines, m.renderSecrets(len(lines))...)
	case tabMembers:
		lines = append(lines, m.renderMembers(len(lines))...)
	case tabSettings:
		lines = append(lines, m.renderSettings(len(lines))...)
	}
	if m.overlay != overlayNone {
		lines = append(lines, m.renderOverlay(len(lines))...)
	}
	return terminalView(strings.Join(lines, "\n"))
}

func terminalView(content string) tea.View {
	view := tea.NewView(content)
	view.AltScreen = true
	view.MouseMode = tea.MouseModeAllMotion
	return view
}

func (m *model) renderTabs(y int) string {
	labels := []string{" 1 Secrets ", " 2 Members ", " 3 Settings "}
	var b strings.Builder
	x := 0
	for i, label := range labels {
		style := tabStyle
		if int(m.tab) == i {
			style = activeTabStyle
		}
		rendered := style.Render(label)
		b.WriteString(rendered)
		m.addHit(hitTab, x, y, lipgloss.Width(rendered), 1, i, "")
		x += lipgloss.Width(rendered)
		b.WriteString(" ")
		x++
	}
	return b.String()
}

func (m *model) renderSecrets(startY int) []string {
	lines := []string{}
	envLabel := fmt.Sprintf(" Environment: %s ▾ ", fallback(m.current, "default"))
	pullLabel := " ⇩ Pull "
	lines = append(lines, sectionStyle.Render(envLabel)+"  "+buttonStyle.Render(pullLabel))
	m.addHit(hitEnvironment, 0, startY, lipgloss.Width(envLabel), 1, 0, "")
	m.addHit(hitPull, lipgloss.Width(envLabel)+2, startY, lipgloss.Width(pullLabel), 1, 0, "")

	if m.environmentOpen() {
		for i, env := range m.envs {
			marker := "  "
			if env.name == m.current {
				marker = "✓ "
			}
			label := "   " + marker + env.name
			lines = append(lines, selectedIf(label, i == m.envCursor))
			m.addHit(hitEnvironmentOption, 0, startY+len(lines)-1, max(24, lipgloss.Width(label)), 1, i, env.name)
		}
		label := "   + Create environment"
		lines = append(lines, selectedIf(label, m.envCursor == len(m.envs)))
		m.addHit(hitCreateEnvironment, 0, startY+len(lines)-1, max(24, lipgloss.Width(label)), 1, 0, "")
	}

	keyWidth := min(24, max(14, (m.contentWidth()-21)/3))
	valueWidth := max(14, m.contentWidth()-keyWidth-21)
	header := fmt.Sprintf("  %-*s  %-*s  ACTIONS", keyWidth, "KEY", valueWidth, "VALUE")
	lines = append(lines, "", tableHeaderStyle.Render(header))
	rowStart := startY + len(lines)
	visible := m.visibleRows()
	end := min(len(m.secrets), m.offset+visible)
	for i := m.offset; i < end; i++ {
		s := m.secrets[i]
		value := strings.Repeat("•", max(8, min(24, len([]rune(s.value)))))
		if m.revealed[s.key] {
			value = s.value
		}
		keyText := truncate(s.key, keyWidth)
		valueText := truncate(value, valueWidth)
		prefix := "  "
		if i == m.cursor {
			prefix = "› "
		}
		row := fmt.Sprintf("%s%-*s  %-*s  [K] [V] [E] [D]", prefix, keyWidth, keyText, valueWidth, valueText)
		lines = append(lines, selectedIf(row, i == m.cursor))
		y := rowStart + i - m.offset
		m.addHit(hitSecretRow, 0, y, max(1, m.width), 1, i, "")
		actionX := 2 + keyWidth + 2 + valueWidth + 2
		m.addHit(hitCopyKey, actionX, y, 3, 1, i, "")
		m.addHit(hitCopyValue, actionX+4, y, 3, 1, i, "")
		m.addHit(hitReveal, actionX+8, y, 3, 1, i, "")
		m.addHit(hitDelete, actionX+12, y, 3, 1, i, "")
	}
	if len(m.secrets) == 0 {
		lines = append(lines, dimStyle.Render("  No secrets yet."))
	}
	if len(m.secrets) > visible {
		lines = append(lines, dimStyle.Render(fmt.Sprintf("  %d–%d of %d", m.offset+1, end, len(m.secrets))))
	}
	lines = append(lines, "", buttonPrimaryStyle.Render(" + Add secret "))
	m.addHit(hitAdd, 0, startY+len(lines)-1, 14, 1, 0, "")
	lines = append(lines, helpStyle.Render("j/k move  space reveal  y/Y copy value/key  a add  e edit  d delete  s environment  p pull  q quit"))
	return lines
}

func (m *model) renderMembers(startY int) []string {
	lines := []string{sectionStyle.Render(" Members ") + "  " + buttonStyle.Render(" ↻ Refresh "), ""}
	m.addHit(hitRefreshMembers, 11, startY, 11, 1, 0, "")
	if len(m.recipients) == 0 {
		lines = append(lines, dimStyle.Render("  No recipients found."))
	} else {
		for _, recipient := range m.recipients {
			lines = append(lines, fmt.Sprintf("  %s  %s", selectedStyle.Render(recipient.Username), dimStyle.Render(recipient.Fingerprint)))
		}
	}
	lines = append(lines, "", helpStyle.Render("r refresh  1/2/3 switch tab  q quit"))
	return lines
}

func (m *model) renderSettings(startY int) []string {
	if m.configEditing {
		lines := []string{sectionStyle.Render(" Edit enbu.toml "), ""}
		lines = append(lines, strings.Split(m.configInput.View(), "\n")...)
		lines = append(lines, "", buttonPrimaryStyle.Render(" Save ")+"  "+buttonStyle.Render(" Cancel "))
		actionY := startY + len(lines) - 1
		m.addHit(hitConfirm, 0, actionY, 6, 1, 0, "")
		m.addHit(hitCancel, 8, actionY, 8, 1, 0, "")
		lines = append(lines, helpStyle.Render("ctrl+s save  esc cancel"))
		return lines
	}
	viewLabel := " </> Code view "
	if m.configCode {
		viewLabel = " ≡ Form view "
	}
	lines := []string{sectionStyle.Render(" enbu.toml ") + "  " + buttonStyle.Render(viewLabel) + "  " + buttonPrimaryStyle.Render(" Edit "), ""}
	viewX := 13
	m.addHit(hitSettingsView, viewX, startY, lipgloss.Width(viewLabel), 1, 0, "")
	m.addHit(hitSettingsEdit, viewX+lipgloss.Width(viewLabel)+2, startY, 6, 1, 0, "")
	if m.configCode {
		for _, line := range strings.Split(strings.TrimRight(m.configContent, "\n"), "\n") {
			lines = append(lines, codeStyle.Render("  "+line))
		}
	} else {
		cfg, err := config.ParseProject(m.configContent)
		if err != nil {
			lines = append(lines, errorStyle.Render("  "+err.Error()))
		} else {
			lines = append(lines, fmt.Sprintf("  Version       %s", selectedStyle.Render(cfg.Version)))
			lines = append(lines, fmt.Sprintf("  Default env   %s", selectedStyle.Render(cfg.CurrentEnvironment())), "")
			for _, name := range cfg.EnvironmentNames() {
				env, _ := cfg.Environment(name)
				lines = append(lines, fmt.Sprintf("  %-20s %s", name, dimStyle.Render(env.Output)))
			}
		}
	}
	lines = append(lines, "", helpStyle.Render("v toggle view  e edit TOML  1/2/3 switch tab  q quit"))
	return lines
}

func (m *model) renderOverlay(startY int) []string {
	lines := []string{"", dialogStyle.Render("────────────────────────────────────────────────────────")}
	title := ""
	switch m.overlay {
	case overlayAdd:
		title = "Add secret"
	case overlayEdit:
		title = "Edit " + m.secrets[m.cursor].key
	case overlayDelete:
		title = "Delete secret"
	case overlayCreateEnvironment:
		title = "Create environment"
	}
	lines = append(lines, dialogTitleStyle.Render("  "+title))
	baseY := startY + len(lines)
	switch m.overlay {
	case overlayAdd:
		lines = append(lines, "  Key    "+m.keyInput.View(), "  Value  "+m.valueInput.View())
		m.addHit(hitInputKey, 9, baseY, max(1, m.keyInput.Width()), 1, 0, "")
		m.addHit(hitInputValue, 9, baseY+1, max(1, m.valueInput.Width()), 1, 0, "")
	case overlayEdit:
		lines = append(lines, "  Value  "+m.valueInput.View())
		m.addHit(hitInputValue, 9, baseY, max(1, m.valueInput.Width()), 1, 0, "")
	case overlayDelete:
		lines = append(lines, fmt.Sprintf("  Delete %s? This cannot be undone.", selectedStyle.Render(m.secrets[m.cursor].key)))
	case overlayCreateEnvironment:
		lines = append(lines, "  Name   "+m.envInput.View())
		m.addHit(hitInputKey, 9, baseY, max(1, m.envInput.Width()), 1, 0, "")
	}
	lines = append(lines, "", buttonPrimaryStyle.Render(" Confirm ")+"  "+buttonStyle.Render(" Cancel "))
	actionY := startY + len(lines) - 1
	m.addHit(hitConfirm, 0, actionY, 9, 1, 0, "")
	m.addHit(hitCancel, 11, actionY, 8, 1, 0, "")
	help := "enter confirm  esc cancel"
	if m.overlay == overlayAdd && m.focusKey {
		help = "enter value  tab switch field  esc cancel"
	}
	lines = append(lines, helpStyle.Render(help))
	return lines
}

func (m *model) startConfigEdit() (tea.Model, tea.Cmd) {
	m.configEditing = true
	m.configCode = true
	m.configDraft = m.configContent
	m.configInput.SetValue(m.configContent)
	cmd := m.configInput.Focus()
	return m, cmd
}

func (m *model) addHit(kind hitKind, x, y, w, h, index int, value string) {
	m.hits = append(m.hits, hitRegion{kind: kind, x: x, y: y, w: w, h: h, index: index, value: value})
}

func (m *model) openAdd() {
	m.overlay = overlayAdd
	m.keyInput.Reset()
	m.valueInput.Reset()
	m.focusKey = true
	m.focusSecretInput()
	m.err = nil
}

func (m *model) openEdit() {
	if len(m.secrets) == 0 {
		return
	}
	m.overlay = overlayEdit
	m.valueInput.SetValue(m.secrets[m.cursor].value)
	m.focusKey = false
	m.focusSecretInput()
	m.err = nil
}

func (m *model) openDelete() {
	if len(m.secrets) > 0 {
		m.overlay = overlayDelete
		m.err = nil
	}
}

func (m *model) openCreateEnvironment() {
	m.overlay = overlayCreateEnvironment
	m.envInput.Reset()
	m.envInput.Focus()
	m.keyInput.Blur()
	m.valueInput.Blur()
	m.err = nil
}

func (m *model) closeOverlay() {
	m.overlay = overlayNone
	m.keyInput.Blur()
	m.valueInput.Blur()
	m.envInput.Blur()
	m.err = nil
}

func (m *model) confirmOverlay() (tea.Model, tea.Cmd) {
	switch m.overlay {
	case overlayAdd:
		secretKey := strings.TrimSpace(m.keyInput.Value())
		if secretKey == "" {
			m.err = fmt.Errorf("key cannot be empty")
			return m, nil
		}
		if m.valueInput.Value() == "" {
			m.err = fmt.Errorf("value cannot be empty")
			return m, nil
		}
		m.loading = true
		return m, m.addSecret(secretKey, m.valueInput.Value())
	case overlayEdit:
		if len(m.secrets) > 0 {
			m.loading = true
			return m, m.editSecret(m.secrets[m.cursor].key, m.valueInput.Value())
		}
	case overlayDelete:
		if len(m.secrets) > 0 {
			m.loading = true
			return m, m.deleteSecret(m.secrets[m.cursor].key)
		}
	case overlayCreateEnvironment:
		name := strings.TrimSpace(m.envInput.Value())
		if !config.ValidEnvironmentName(name) {
			m.err = fmt.Errorf("invalid environment name %q", name)
			return m, nil
		}
		m.loading = true
		return m, m.createEnvironment(name)
	}
	return m, nil
}

func (m *model) focusSecretInput() {
	if m.overlay == overlayCreateEnvironment {
		m.envInput.Focus()
		return
	}
	if m.focusKey && m.overlay == overlayAdd {
		m.keyInput.Focus()
		m.valueInput.Blur()
	} else {
		m.keyInput.Blur()
		m.valueInput.Focus()
	}
}

func (m *model) environmentOpen() bool { return m.envMenuOpen }
func (m *model) openEnvironment() {
	m.envMenuOpen = true
	for i, env := range m.envs {
		if env.name == m.current {
			m.envCursor = i
			break
		}
	}
}
func (m *model) closeEnvironment() { m.envMenuOpen = false }

func (m *model) selectEnvironment(name string) (tea.Model, tea.Cmd) {
	m.closeEnvironment()
	if name == m.current {
		return m, nil
	}
	m.loading = true
	return m, m.switchEnv(name)
}

func (m *model) toggleReveal(index int) {
	if index < 0 || index >= len(m.secrets) {
		return
	}
	secretKey := m.secrets[index].key
	m.revealed[secretKey] = !m.revealed[secretKey]
}

func (m *model) copySecret(index int, copyKey bool) (tea.Model, tea.Cmd) {
	if index < 0 || index >= len(m.secrets) {
		return m, nil
	}
	value := m.secrets[index].value
	label := "value"
	if copyKey {
		value = m.secrets[index].key
		label = "key"
	}
	copyFn := m.copyToClipboard
	return m, func() tea.Msg {
		if err := copyFn(value); err != nil {
			return errMsg{err: fmt.Errorf("copying %s: %w", label, err)}
		}
		return clipboardDoneMsg{message: "Copied " + label}
	}
}

func (m *model) visibleRows() int  { return max(1, m.height-15) }
func (m *model) contentWidth() int { return max(58, m.width) }
func (m *model) maxOffset() int    { return max(0, len(m.secrets)-m.visibleRows()) }
func (m *model) ensureCursorVisible() {
	if m.cursor < m.offset {
		m.offset = m.cursor
	}
	if m.cursor >= m.offset+m.visibleRows() {
		m.offset = m.cursor - m.visibleRows() + 1
	}
}
func (m *model) clampCursor() {
	m.cursor = max(0, min(m.cursor, len(m.secrets)-1))
	m.offset = max(0, min(m.offset, m.maxOffset()))
}

func (m *model) loadWorkspace() tea.Cmd {
	return func() tea.Msg {
		if m.app == nil {
			secrets := make(map[string]string)
			for _, entry := range demoSecretsByEnv[demoCurrent] {
				secrets[entry.key] = entry.value
			}
			return workspaceLoadedMsg{secrets: secrets, envs: demoEnvs, current: demoCurrent, repository: "enbu-net/enbu"}
		}
		envs, err := m.app.ListEnvironments()
		if err != nil {
			return errMsg{err}
		}
		items := make([]envItem, 0, len(envs))
		current := ""
		for _, env := range envs {
			items = append(items, envItem{name: env.Name, isCurrent: env.IsCurrent})
			if env.IsCurrent {
				current = env.Name
			}
		}
		secrets, err := m.app.ListSecrets(context.Background(), current)
		if err != nil {
			return errMsg{err}
		}
		repository := ""
		if m.app.RepoDetector != nil {
			owner, repo, repoErr := m.app.RepoDetector.LoadRepo()
			if repoErr == nil {
				repository = owner + "/" + repo
			}
		}
		return workspaceLoadedMsg{secrets: secrets, envs: items, current: current, repository: repository}
	}
}

func (m *model) loadRecipients() tea.Cmd {
	return func() tea.Msg {
		if m.app == nil {
			return recipientsLoadedMsg{recipients: demoRecipients}
		}
		list, err := m.app.ListRecipients(context.Background())
		if err != nil {
			return errMsg{err}
		}
		return recipientsLoadedMsg{recipients: list}
	}
}

func (m *model) loadConfig() tea.Cmd {
	return func() tea.Msg {
		if m.app == nil {
			return configLoadedMsg{content: demoConfigContent}
		}
		content, err := m.app.ReadConfig()
		if err != nil {
			return errMsg{err}
		}
		return configLoadedMsg{content: content}
	}
}

func (m *model) saveConfig(content string) tea.Cmd {
	return func() tea.Msg {
		if m.app == nil {
			demoConfigContent = content
			return configSavedMsg{}
		}
		if err := m.app.WriteConfig(content); err != nil {
			return errMsg{err}
		}
		return configSavedMsg{}
	}
}

func (m *model) addSecret(secretKey, value string) tea.Cmd {
	return func() tea.Msg {
		if m.app == nil {
			for _, secret := range demoSecretsByEnv[demoCurrent] {
				if secret.key == secretKey {
					return errMsg{err: fmt.Errorf("secret %s already exists", secretKey)}
				}
			}
			demoSecretsByEnv[demoCurrent] = append(demoSecretsByEnv[demoCurrent], secretEntry{key: secretKey, value: value})
			return operationDoneMsg{message: "Added " + secretKey}
		}
		if err := m.app.AddSecret(context.Background(), m.current, secretKey, value); err != nil {
			return errMsg{err}
		}
		return operationDoneMsg{message: "Added " + secretKey}
	}
}

func (m *model) editSecret(secretKey, value string) tea.Cmd {
	return func() tea.Msg {
		if m.app == nil {
			for i, secret := range demoSecretsByEnv[demoCurrent] {
				if secret.key == secretKey {
					demoSecretsByEnv[demoCurrent][i].value = value
				}
			}
			return operationDoneMsg{message: "Updated " + secretKey}
		}
		if err := m.app.EditSecret(context.Background(), m.current, secretKey, value); err != nil {
			return errMsg{err}
		}
		return operationDoneMsg{message: "Updated " + secretKey}
	}
}

func (m *model) deleteSecret(secretKey string) tea.Cmd {
	return func() tea.Msg {
		if m.app == nil {
			updated := make([]secretEntry, 0, len(demoSecretsByEnv[demoCurrent]))
			for _, secret := range demoSecretsByEnv[demoCurrent] {
				if secret.key != secretKey {
					updated = append(updated, secret)
				}
			}
			demoSecretsByEnv[demoCurrent] = updated
			return operationDoneMsg{message: "Deleted " + secretKey}
		}
		if err := m.app.DeleteSecret(context.Background(), m.current, secretKey); err != nil {
			return errMsg{err}
		}
		return operationDoneMsg{message: "Deleted " + secretKey}
	}
}

func (m *model) switchEnv(name string) tea.Cmd {
	return func() tea.Msg {
		if m.app == nil {
			demoCurrent = name
			for i := range demoEnvs {
				demoEnvs[i].isCurrent = demoEnvs[i].name == name
			}
			return operationDoneMsg{message: "Switched to " + name}
		}
		if err := m.app.SwitchEnvironment(name); err != nil {
			return errMsg{err}
		}
		return operationDoneMsg{message: "Switched to " + name}
	}
}

func (m *model) createEnvironment(name string) tea.Cmd {
	return func() tea.Msg {
		if m.app == nil {
			demoEnvs = append(demoEnvs, envItem{name: name, isCurrent: true})
			for i := range demoEnvs {
				demoEnvs[i].isCurrent = demoEnvs[i].name == name
			}
			demoSecretsByEnv[name] = nil
			demoCurrent = name
			return operationDoneMsg{message: "Created " + name}
		}
		if err := m.app.CreateEnvironment(name); err != nil {
			return errMsg{err}
		}
		return operationDoneMsg{message: "Created " + name}
	}
}

func (m *model) pullSecrets() tea.Cmd {
	return func() tea.Msg {
		if m.app == nil {
			return operationDoneMsg{message: "Wrote environment file"}
		}
		if err := m.app.PullSecretsToFile(context.Background(), m.current); err != nil {
			return errMsg{err}
		}
		return operationDoneMsg{message: "Wrote environment file"}
	}
}

func mapToEntries(secrets map[string]string) []secretEntry {
	entries := make([]secretEntry, 0, len(secrets))
	for secretKey, value := range secrets {
		entries = append(entries, secretEntry{key: secretKey, value: value})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].key < entries[j].key })
	return entries
}

func selectedIf(value string, selected bool) string {
	if selected {
		return selectedRowStyle.Render(value)
	}
	return value
}

func truncate(value string, width int) string {
	if lipgloss.Width(value) <= width {
		return value
	}
	runes := []rune(value)
	if len(runes) > width {
		runes = runes[:width]
	}
	for len(runes) > 0 && lipgloss.Width(string(runes))+1 > width {
		runes = runes[:len(runes)-1]
	}
	return string(runes) + "…"
}

func fallback(value, defaultValue string) string {
	if value == "" {
		return defaultValue
	}
	return value
}
