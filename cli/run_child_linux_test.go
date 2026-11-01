package cli

import (
	"bufio"
	"bytes"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// TestBindToEnbuHelperProcess stands in for enbu: it starts a long sleep bound
// to itself, prints the sleep's PID and waits for it.
func TestBindToEnbuHelperProcess(t *testing.T) {
	if os.Getenv("ENBU_TEST_BIND_HELPER") != "1" {
		return
	}
	child := exec.Command("sleep", "30")
	release := bindToEnbu(child)
	defer release()
	if err := child.Start(); err != nil {
		os.Exit(2)
	}
	_, _ = os.Stdout.WriteString(strconv.Itoa(child.Process.Pid) + "\n")
	_ = child.Wait()
	os.Exit(0)
}

// A command started by enbu run ends when enbu is killed with SIGKILL, which
// enbu cannot forward.
func TestBindToEnbuKillsTheCommandWithEnbu(t *testing.T) {
	if _, err := exec.LookPath("sleep"); err != nil {
		t.Skip("sleep not found")
	}
	enbu := exec.Command(os.Args[0], "-test.run=^TestBindToEnbuHelperProcess$")
	enbu.Env = append(os.Environ(), "ENBU_TEST_BIND_HELPER=1")
	stdout, err := enbu.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := enbu.Start(); err != nil {
		t.Fatal(err)
	}
	line, err := bufio.NewReader(stdout).ReadString('\n')
	if err != nil {
		_ = enbu.Process.Kill()
		t.Fatalf("helper did not start the command: %v", err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(line))
	if err != nil {
		t.Fatalf("helper printed %q", line)
	}
	if err := enbu.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = enbu.Wait()
	for deadline := time.Now().Add(10 * time.Second); alive(pid); {
		if time.Now().After(deadline) {
			_ = syscall.Kill(pid, syscall.SIGKILL)
			t.Fatalf("command %d outlived enbu", pid)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// alive reports whether pid runs. A zombie has ended: it waits only for a
// parent that reaps it, which an init without a reaper may never do.
func alive(pid int) bool {
	stat, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return false
	}
	// The state follows the command name, which is in parentheses.
	i := bytes.LastIndexByte(stat, ')')
	return i < 0 || i+2 >= len(stat) || stat[i+2] != 'Z'
}
