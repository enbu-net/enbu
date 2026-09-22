//go:build wasip1

package tui

import "testing"

func TestDemoUsesWASITerminalOptions(t *testing.T) {
	t.Setenv("COLUMNS", "96")
	t.Setenv("LINES", "28")
	if options := demoProgramOptions(); len(options) != 4 {
		t.Fatalf("demoProgramOptions() = %d options, want WASI input, output, signal, and size options", len(options))
	}
}
