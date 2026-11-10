package selfupdate

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"time"
)

// waitPIDEnv tells a relaunched app which process to wait for: the app that
// installed the update holds the single-instance lock until it exits.
const waitPIDEnv = "ENBU_UPDATE_WAIT_PID"

// Here describes the running installation.
func Here(goos, version string) Installation {
	exe, err := os.Executable()
	if err == nil {
		if resolved, err := filepath.EvalSymlinks(exe); err == nil {
			exe = resolved
		}
	}
	return Installation{
		GOOS:       goos,
		Version:    version,
		Executable: exe,
		Writable:   writable,
		Exists: func(path string) bool {
			_, err := os.Stat(path)
			return err == nil
		},
	}
}

// writable tries what an update does: create a file in dir and remove it.
func writable(dir string) bool {
	f, err := os.CreateTemp(dir, ".enbu-update-check-*")
	if err != nil {
		return false
	}
	name := f.Name()
	_ = f.Close()
	return os.Remove(name) == nil
}

// Relaunch starts executable again, telling it to wait until this process
// has exited. The caller quits right after.
func Relaunch(executable string) error {
	cmd := exec.Command(executable)
	cmd.Env = append(os.Environ(), waitPIDEnv+"="+strconv.Itoa(os.Getpid()))
	if err := cmd.Start(); err != nil {
		return err
	}
	return cmd.Process.Release()
}

// WaitForPrevious blocks, for at most timeout, until the app that relaunched
// this one has exited, and clears the variable so children do not inherit it.
func WaitForPrevious(timeout time.Duration) {
	value := os.Getenv(waitPIDEnv)
	if value == "" {
		return
	}
	_ = os.Unsetenv(waitPIDEnv)
	pid, err := strconv.Atoi(value)
	if err != nil || pid <= 0 {
		return
	}
	deadline := time.Now().Add(timeout)
	for processAlive(pid) && time.Now().Before(deadline) {
		time.Sleep(100 * time.Millisecond)
	}
}
