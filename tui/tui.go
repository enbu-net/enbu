// Package tui renders a metadata-only view over a typed host Workspace.
package tui

import (
	"context"
	"errors"
	"fmt"
	"strings"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"github.com/enbu-net/enbu/pkg/artifact"
	"github.com/enbu-net/enbu/pkg/host"
)

type loadedMsg struct {
	snapshot  host.WorkspaceSnapshot
	resources []host.ResourceMetadata
	err       error
}

type model struct {
	ctx       context.Context
	workspace *host.Workspace
	snapshot  host.WorkspaceSnapshot
	resources []host.ResourceMetadata
	err       error
	loading   bool
	width     int
	demo      bool
}

func NewModel(ctx context.Context, workspace *host.Workspace) tea.Model {
	return &model{ctx: ctx, workspace: workspace, loading: true}
}

func (model *model) Init() tea.Cmd { return model.load }

func (model *model) load() tea.Msg {
	if model.demo {
		return loadedMsg{snapshot: model.snapshot, resources: model.resources}
	}
	if model.workspace == nil {
		return loadedMsg{err: errors.New("tui: nil workspace")}
	}
	snapshot, err := model.workspace.Snapshot(model.ctx)
	if err != nil {
		return loadedMsg{err: err}
	}
	if len(snapshot.Frontier) != 1 {
		return loadedMsg{err: errors.New("tui: workspace frontier is not singular")}
	}
	var resources []host.ResourceMetadata
	var cursor host.QueryCursor
	for {
		page, err := model.workspace.ListResources(model.ctx, host.ListResourcesRequest{
			AtCommit: snapshot.Frontier[0], PageSize: host.MaxQueryPageSize, Cursor: cursor,
		})
		if err != nil {
			return loadedMsg{err: err}
		}
		resources = append(resources, page.Resources...)
		if page.Next == "" {
			break
		}
		cursor = page.Next
	}
	return loadedMsg{snapshot: snapshot, resources: resources}
}

func (model *model) Update(message tea.Msg) (tea.Model, tea.Cmd) {
	switch value := message.(type) {
	case tea.KeyPressMsg:
		switch value.String() {
		case "q", "ctrl+c", "esc":
			return model, tea.Quit
		case "r":
			model.loading = true
			model.err = nil
			return model, model.load
		}
	case tea.WindowSizeMsg:
		model.width = value.Width
	case loadedMsg:
		model.loading = false
		model.snapshot, model.resources, model.err = value.snapshot, value.resources, value.err
	}
	return model, nil
}

func (model *model) View() tea.View {
	title := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("99")).Render("enbu · encrypted resources")
	muted := lipgloss.NewStyle().Foreground(lipgloss.Color("245"))
	lines := []string{title, muted.Render("metadata only · secret payloads remain inside the trusted host"), ""}
	switch {
	case model.loading:
		lines = append(lines, "Loading workspace…")
	case model.err != nil:
		lines = append(lines, "Workspace unavailable.")
	case len(model.resources) == 0:
		lines = append(lines, "No resources.")
	default:
		lines = append(lines, fmt.Sprintf("%d resources · %d commits", model.snapshot.ResourceCount, model.snapshot.CommitCount), "")
		for _, resource := range model.resources {
			name := resource.Metadata.Name
			if name == "" {
				name = "Unnamed resource"
			}
			lines = append(lines, fmt.Sprintf("  %-12s %s", resource.Kind, name), muted.Render("               "+string(resource.UID)))
		}
	}
	lines = append(lines, "", muted.Render("r refresh  ·  q quit"))
	view := tea.NewView(strings.Join(lines, "\n"))
	view.AltScreen = true
	return view
}

func Run(ctx context.Context, workspace *host.Workspace) error {
	if ctx == nil || workspace == nil {
		return errors.New("tui: context and workspace are required")
	}
	_, err := tea.NewProgram(NewModel(ctx, workspace), tea.WithContext(ctx)).Run()
	return err
}

func RunDemo() error {
	resourceID, _ := artifact.ParseUUID("22222222-2222-4222-8222-222222222222")
	model := &model{ctx: context.Background(), demo: true, loading: true,
		snapshot:  host.WorkspaceSnapshot{ResourceCount: 2, CommitCount: 4},
		resources: []host.ResourceMetadata{{Kind: artifact.KindCollection, UID: resourceID, Metadata: artifact.Metadata{Name: "workspace"}}},
	}
	_, err := tea.NewProgram(model).Run()
	return err
}
