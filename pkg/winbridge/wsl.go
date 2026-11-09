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

var (
	procVersion = "/proc/version"
	// wslMarkers exist in a WSL 2 distribution: the interop registrations,
	// and the directories WSL mounts whether or not interop is on. A Linux
	// container on a WSL 2 kernel (Docker Desktop, a devcontainer) shares
	// /proc/version but none of these.
	wslMarkers = []string{"/proc/sys/fs/binfmt_misc/WSLInterop", "/proc/sys/fs/binfmt_misc/WSLInterop-late", "/run/WSL", "/mnt/wsl"}
)

// interopHint is added when enbu.exe cannot start: WSL runs Windows programs
// only while interop is on.
const interopHint = "WSL starts Windows programs only with interop on; check that /etc/wsl.conf does not set [interop] enabled=false"

// InWSL reports whether this process runs inside WSL 1 or 2. It checks what
// WSL itself sets, like Git Credential Manager: WSL_INTEROP (WSL 2) or
// WSL_DISTRO_NAME, then "microsoft" in /proc/version. A WSL 2 kernel counts
// only with a WSL marker, so a Linux container on Docker Desktop keeps its own
// keystore; a WSL distribution with interop off still counts, and fails.
var InWSL = sync.OnceValue(func() bool { return detect(os.Getenv, procVersion, wslMarkers) })

func detect(getenv func(string) string, versionFile string, markers []string) bool {
	if runtime.GOOS != "linux" {
		return false
	}
	if getenv("WSL_INTEROP") != "" || getenv("WSL_DISTRO_NAME") != "" {
		return true
	}
	b, err := os.ReadFile(versionFile)
	version := bytes.ToLower(b)
	if err != nil || !bytes.Contains(version, []byte("microsoft")) {
		return false
	}
	// WSL 2 kernels say "microsoft-standard" (older ones lack "WSL2"); WSL 1
	// says "Microsoft" only, and runs no containers.
	if !bytes.Contains(version, []byte("wsl2")) && !bytes.Contains(version, []byte("microsoft-standard")) {
		return true
	}
	for _, f := range markers {
		if _, err := os.Stat(f); err == nil {
			return true
		}
	}
	return false
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
