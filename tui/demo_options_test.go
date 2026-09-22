//go:build !wasip1

package tui

import "testing"

func TestDemoUsesNativeTerminalDefaults(t *testing.T) {
	if options := demoProgramOptions(); options != nil {
		t.Fatalf("demoProgramOptions() = %d options, want native defaults", len(options))
	}
}
