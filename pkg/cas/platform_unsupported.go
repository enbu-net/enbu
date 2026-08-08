//go:build !linux && !darwin && !windows

package cas

func rejectPlatformSpecial(string) error { return nil }
