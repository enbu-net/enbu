//go:build windows

package process

import (
	"os/exec"
	"testing"
)

func TestHideWindowSetsSysProcAttr(t *testing.T) {
	cmd := exec.Command("git", "version")
	HideWindow(cmd)
	if cmd.SysProcAttr == nil {
		t.Fatal("SysProcAttr is nil")
	}
	if !cmd.SysProcAttr.HideWindow {
		t.Fatal("HideWindow is false")
	}
}
