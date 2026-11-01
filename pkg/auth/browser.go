package auth

import (
	"os/exec"
	"path/filepath"
	"runtime"
)

func OpenBrowser(url string) error {
	cmd := browserCommand(runtime.GOOS, url)
	if err := cmd.Start(); err != nil {
		return err
	}
	go func() { _ = cmd.Wait() }()
	return nil
}

// browserCommand names the macOS and Windows openers by their full paths, so a
// program of the same name earlier in PATH cannot receive the OAuth URL. Other
// platforms still find xdg-open through PATH, where it lives in different
// directories.
func browserCommand(goos, url string) *exec.Cmd {
	var cmd *exec.Cmd
	switch goos {
	case "darwin":
		cmd = exec.Command("/usr/bin/open", url)
	case "windows":
		cmd = exec.Command(filepath.Join(systemDirectory(), "rundll32.exe"), "url.dll,FileProtocolHandler", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	return cmd
}
