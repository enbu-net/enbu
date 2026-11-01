//go:build !linux

package process

// Harden has nothing to set on this platform yet.
func Harden() error { return nil }
