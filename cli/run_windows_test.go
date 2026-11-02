package cli

import (
	"os"
	"os/exec"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

// TestRunJobHelperProcess is the child of TestKillOnCloseJobEndsProcesses: it
// waits long enough that only the job can end it in time.
func TestRunJobHelperProcess(t *testing.T) {
	if os.Getenv("ENBU_TEST_JOB_HELPER") != "1" {
		return
	}
	time.Sleep(30 * time.Second)
	os.Exit(0)
}

func TestKillOnCloseJobEndsProcesses(t *testing.T) {
	job, err := newKillOnCloseJob()
	if err != nil {
		t.Fatal(err)
	}
	child := exec.Command(os.Args[0], "-test.run=^TestRunJobHelperProcess$")
	child.Env = append(os.Environ(), "ENBU_TEST_JOB_HELPER=1")
	if err := child.Start(); err != nil {
		_ = windows.CloseHandle(job)
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = child.Process.Kill() })
	process, err := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE, false, uint32(child.Process.Pid))
	if err != nil {
		_ = windows.CloseHandle(job)
		t.Fatal(err)
	}
	defer func() { _ = windows.CloseHandle(process) }()
	if err := windows.AssignProcessToJobObject(job, process); err != nil {
		_ = windows.CloseHandle(job)
		t.Fatal(err)
	}
	// Closing the last handle stands in for enbu ending.
	if err := windows.CloseHandle(job); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- child.Wait() }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("the process exited normally instead of being ended by the job")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the process outlived the job")
	}
}

func TestMergedEnvFoldsCaseOnWindows(t *testing.T) {
	got := mergedEnv([]string{"Path=C:\\Windows"}, map[string]string{"PATH": "C:\\tools"}, false)
	if len(got) != 1 || got[0] != "PATH=C:\\tools" {
		t.Fatalf("mergedEnv = %q, want one PATH", got)
	}
}
