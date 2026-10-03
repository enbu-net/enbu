//go:build linux || darwin

package cas

func rejectPlatformSpecial(string) error { return nil }
