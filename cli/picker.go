package cli

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	tea "charm.land/bubbletea/v2"
	"github.com/enbu-net/enbu/pkg/apperr"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

// pickerItem is one choice. Detail is shown dimmed on the same line.
type pickerItem struct {
	Label  string
	Detail string
}

var errPickerCancelled = errors.New("selection cancelled")

// interactive reports whether the command can ask the user questions: stdin and
// stderr are terminals and the output is not JSON.
func interactive(cmd *cobra.Command) bool {
	if jsonEnabled(cmd) {
		return false
	}
	return stdioIsTerminal()
}

// stdioIsTerminal is a variable so tests can drive the prompts without a TTY.
var stdioIsTerminal = func() bool {
	return term.IsTerminal(int(os.Stdin.Fd())) && term.IsTerminal(int(os.Stderr.Fd()))
}

// pick shows items and returns the index of the chosen one. The menu is drawn
// on stderr so stdout stays clean.
func pick(cmd *cobra.Command, title string, items []pickerItem) (int, error) {
	if len(items) == 0 {
		return -1, errors.New("nothing to choose from")
	}
	m := &pickerModel{title: title, items: items, chosen: -1}
	final, err := tea.NewProgram(m, tea.WithOutput(cmd.ErrOrStderr())).Run()
	if err != nil {
		return -1, err
	}
	if idx := final.(*pickerModel).chosen; idx >= 0 {
		return idx, nil
	}
	return -1, errPickerCancelled
}

type pickerModel struct {
	title  string
	items  []pickerItem
	cursor int
	chosen int
}

func (m *pickerModel) Init() tea.Cmd { return nil }

func (m *pickerModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	key, ok := msg.(tea.KeyPressMsg)
	if !ok {
		return m, nil
	}
	switch key.String() {
	case "up", "k":
		if m.cursor > 0 {
			m.cursor--
		}
	case "down", "j":
		if m.cursor < len(m.items)-1 {
			m.cursor++
		}
	case "enter":
		m.chosen = m.cursor
		return m, tea.Quit
	case "q", "esc", "ctrl+c":
		return m, tea.Quit
	}
	return m, nil
}

func (m *pickerModel) View() tea.View {
	var b strings.Builder
	fmt.Fprintf(&b, "%s\n\n", m.title)
	for i, item := range m.items {
		cursor := "  "
		if i == m.cursor {
			cursor = "> "
		}
		fmt.Fprintf(&b, "%s%s", cursor, item.Label)
		if item.Detail != "" {
			fmt.Fprintf(&b, "  %s", item.Detail)
		}
		b.WriteString("\n")
	}
	b.WriteString("\n↑/↓ select · enter confirm · q cancel\n")
	return tea.NewView(b.String())
}

// confirm asks a yes/no question, defaulting to no.
func confirm(cmd *cobra.Command, question string) (bool, error) {
	_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "%s [y/N] ", question)
	line, err := bufio.NewReader(cmd.InOrStdin()).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return false, err
	}
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "y", "yes":
		return true, nil
	}
	return false, nil
}

func cancelled(cmd *cobra.Command) error {
	humanErrorf(cmd, "Cancelled\n")
	return apperr.New(apperr.CodeInvalidArgument, "cancelled", nil)
}
