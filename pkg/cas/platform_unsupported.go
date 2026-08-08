//go:build !linux && !darwin && !windows

package cas

import "os"

func syncDirectory(string) error { return nil }

func openNoFollow(path string) (*os.File, error) { return os.Open(path) }

func rejectPlatformSpecial(string) error { return nil }
