//go:build !windows

package cli

// containCommand has nothing to do here: termination signals sent to enbu are
// forwarded to the command, which ends it with enbu.
func containCommand() error { return nil }
