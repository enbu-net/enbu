package tui

import "testing"

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
