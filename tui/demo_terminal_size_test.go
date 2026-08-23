package tui

import (
	"strings"
	"testing"

	"charm.land/bubbles/v2/spinner"
)

func TestDemoTerminalDimension(t *testing.T) {
	tests := []struct {
		name     string
		value    string
		fallback int
		want     int
	}{
		{name: "valid", value: "96", fallback: 100, want: 96},
		{name: "empty", value: "", fallback: 100, want: 100},
		{name: "invalid", value: "wide", fallback: 100, want: 100},
		{name: "zero", value: "0", fallback: 100, want: 100},
		{name: "negative", value: "-1", fallback: 100, want: 100},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := demoTerminalDimension(tt.value, tt.fallback); got != tt.want {
				t.Fatalf("demoTerminalDimension(%q, %d) = %d, want %d", tt.value, tt.fallback, got, tt.want)
			}
		})
	}
}

func TestDemoDoesNotScheduleHiddenSpinnerFrames(t *testing.T) {
	m := newDemoModel()
	if m.animateSpinner {
		t.Fatal("demo spinner animation is enabled")
	}
	_, cmd := m.Update(spinner.TickMsg{})
	if cmd != nil {
		t.Fatal("hidden demo spinner scheduled another frame")
	}
}

func TestDemoTabsSwitchWithoutLoadingFrames(t *testing.T) {
	m := newDemoModel()

	_, cmd := m.Update(keyMsg("2"))
	if cmd != nil || m.loading || m.tab != tabMembers {
		t.Fatalf("members tab: cmd=%v loading=%v tab=%d", cmd != nil, m.loading, m.tab)
	}
	if view := m.View().Content; !strings.Contains(view, "octocat") || strings.Contains(view, "Loading") {
		t.Fatalf("members view is not ready: %q", view)
	}

	_, cmd = m.Update(keyMsg("1"))
	if cmd != nil || m.loading || m.tab != tabSecrets {
		t.Fatalf("secrets tab: cmd=%v loading=%v tab=%d", cmd != nil, m.loading, m.tab)
	}
}
