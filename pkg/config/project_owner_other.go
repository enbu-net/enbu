//go:build !linux && !darwin

package config

import "os"

// Unix uid/gid ownership is not represented on these platforms.
func preserveProjectOwner(*os.File, os.FileInfo) error { return nil }
