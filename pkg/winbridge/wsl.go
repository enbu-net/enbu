// Package winbridge lets enbu inside WSL keep its keys in Windows. The WSL
// enbu starts the Windows-native enbu.exe once per process
// (`enbu.exe identity bridge --stdio`) and asks it for the key operations
// only: create, unwrap, sign, and the GitHub token. Private keys, the TPM and
// Windows Hello stay in Windows; storage, git and files stay in WSL, so no
// path crosses the boundary.
package winbridge

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"sync"
)

const (
	// ExeEnv names the Windows enbu.exe explicitly, before PATH is searched.
	ExeEnv = "ENBU_WINDOWS_EXE"
	exe    = "enbu.exe"
)

var procVersion = "/proc/version"

// interopHint is added when enbu.exe cannot start: WSL runs Windows programs
// only while interop is on.
const interopHint = "WSL starts Windows programs only with interop on; check that /etc/wsl.conf does not set [interop] enabled=false"

// InWSL reports whether this process runs inside WSL 1 or 2. It checks what
// WSL itself sets, like Git Credential Manager: WSL_INTEROP (WSL 2) or
// WSL_DISTRO_NAME, then "microsoft" in /proc/version.
var InWSL = sync.OnceValue(func() bool { return detect(os.Getenv, procVersion) })

func detect(getenv func(string) string, versionFile string) bool {
	if runtime.GOOS != "linux" {
		return false
	}
	if getenv("WSL_INTEROP") != "" || getenv("WSL_DISTRO_NAME") != "" {
		return true
	}
	b, err := os.ReadFile(versionFile)
	return err == nil && bytes.Contains(bytes.ToLower(b), []byte("microsoft"))
}

// Locate finds the Windows enbu.exe: ENBU_WINDOWS_EXE, else enbu.exe on PATH
// (WSL appends the Windows PATH by default, so winget and scoop installs are
// found). It says what to fix when enbu.exe is missing.
func Locate() (string, error) {
	if p := os.Getenv(ExeEnv); p != "" {
		return p, nil
	}
	p, err := exec.LookPath(exe)
	if err != nil {
		return "", errors.New("the Windows enbu.exe was not found on PATH: install enbu on Windows too (the same version as in WSL), or set " + ExeEnv + " to its path; inside WSL, enbu keeps its keys in Windows")
	}
	return p, nil
}

// RunWindows runs the Windows enbu.exe with args on this terminal, for a
// command such as `auth login` that Windows does as a whole.
func RunWindows(ctx context.Context, stdin io.Reader, stdout, stderr io.Writer, args ...string) error {
	path, err := Locate()
	if err != nil {
		return err
	}
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = stdin, stdout, stderr
	if err := cmd.Run(); err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			return err
		}
		return fmt.Errorf("could not start the Windows %s (%s): %w; %s", exe, path, err, interopHint)
	}
	return nil
}
