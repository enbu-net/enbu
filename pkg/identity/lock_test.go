package identity

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestCreationLockProcess(t *testing.T) {
	path := os.Getenv("ENBU_TEST_CREATION_LOCK")
	if path == "" {
		return
	}
	f, err := acquireCreationLock(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	fmt.Println("locked")
	// The parent kills this process while it owns the lock.
	time.Sleep(time.Minute)
}

func TestCreationLockReleasedAfterProcessDeath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity.lockfile")
	cmd := exec.Command(os.Args[0], "-test.run=^TestCreationLockProcess$")
	cmd.Env = append(os.Environ(), "ENBU_TEST_CREATION_LOCK="+path)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	ready := make(chan string, 1)
	go func() {
		scanner := bufio.NewScanner(stdout)
		if scanner.Scan() {
			ready <- scanner.Text()
		} else {
			ready <- "process exited before acquiring lock"
		}
	}()
	select {
	case line := <-ready:
		if line != "locked" {
			t.Fatal(line)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for lock holder")
	}
	if f, err := acquireCreationLock(path); err == nil {
		_ = f.Close()
		t.Fatal("acquired another process's lock")
	}
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = cmd.Wait()
	f, err := acquireCreationLock(path)
	if err != nil {
		t.Fatalf("lock survived process death: %v", err)
	}
	_ = f.Close()
	// Reopening the retained file must also work after a normal close.
	f, err = acquireCreationLock(path)
	if err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
}
