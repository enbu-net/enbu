//go:build !linux

package cli

import "os/exec"

// bindToEnbu has no parent-death signal to set outside Linux.
func bindToEnbu(*exec.Cmd) (release func()) { return func() {} }
