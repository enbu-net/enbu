//go:build !windows

package process

import "os/exec"

func HideWindow(_ *exec.Cmd) {}
