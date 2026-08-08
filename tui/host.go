package tui

import (
	"context"
	"errors"

	tea "charm.land/bubbletea/v2"
	"github.com/enbu-net/enbu/pkg/client"
	"github.com/enbu-net/enbu/pkg/host"
)

type hostStartMsg struct {
	op  client.Operation
	err error
}

type hostProgressMsg struct {
	event client.Event
}

type hostDoneMsg struct {
	err error
}

// HostModel is the Bubble Tea adapter for a single host operation. It renders
// only phase names and sequence numbers; resource values remain in Go.
type HostModel struct {
	controller *client.Controller
	ctx        context.Context
	action     string
	run        host.Action
	op         client.Operation
	started    bool
	done       bool
	err        error
	last       client.Event
}

func NewHostModel(ctx context.Context, controller *client.Controller, action string, run host.Action) *HostModel {
	if ctx == nil {
		ctx = context.Background()
	}
	return &HostModel{ctx: ctx, controller: controller, action: action, run: run}
}

func (m *HostModel) Init() tea.Cmd {
	return func() tea.Msg {
		if m.controller == nil {
			return hostStartMsg{err: errors.New("tui: nil host controller")}
		}
		op, err := m.controller.Start(m.ctx, m.action, m.run)
		return hostStartMsg{op: op, err: err}
	}
}

func (m *HostModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch value := msg.(type) {
	case tea.KeyPressMsg:
		if value.String() == "q" || value.String() == "ctrl+c" {
			if m.started && !m.done {
				_ = m.controller.Cancel(m.op.ID)
			}
			return m, tea.Quit
		}
	case hostStartMsg:
		if value.err != nil {
			m.err = value.err
			m.done = true
			return m, nil
		}
		m.op = value.op
		m.started = true
		return m, m.next()
	case hostProgressMsg:
		m.last = value.event
		return m, m.next()
	case hostDoneMsg:
		m.err = value.err
		m.done = true
	}
	return m, nil
}

func (m *HostModel) next() tea.Cmd {
	return func() tea.Msg {
		if event, ok := <-m.op.Progress; ok {
			return hostProgressMsg{event: event}
		}
		result := <-m.op.Done
		return hostDoneMsg{err: result.Err}
	}
}

func (m *HostModel) LastEvent() client.Event { return m.last }
func (m *HostModel) Done() bool              { return m.done }
func (m *HostModel) Err() error              { return m.err }

func (m *HostModel) View() tea.View {
	if m.err != nil {
		return tea.NewView("operation failed")
	}
	if m.done {
		return tea.NewView("operation complete")
	}
	if !m.started {
		return tea.NewView("starting operation")
	}
	return tea.NewView(m.last.Phase)
}

// RunHost is the TUI entry point for host-backed operations. A caller chooses
// the operation; this package never invents a repository or global workspace.
func RunHost(ctx context.Context, controller *client.Controller, action string, run host.Action) error {
	model := NewHostModel(ctx, controller, action, run)
	program := tea.NewProgram(model)
	result, err := program.Run()
	if err != nil {
		return err
	}
	if value, ok := result.(*HostModel); ok {
		return value.Err()
	}
	return nil
}
