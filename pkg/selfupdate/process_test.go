package selfupdate

import (
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/enbu-net/enbu/pkg/clock"
)

func TestProcessAlive(t *testing.T) {
	if !processAlive(os.Getpid()) {
		t.Error("this process is not alive")
	}
}

func TestWaitForPreviousReturnsOnceTheProcessIsGone(t *testing.T) {
	t.Setenv(waitPIDEnv, strconv.Itoa(1<<30))
	start := time.Now()
	WaitForPrevious(clock.New(), 5*time.Second)
	if time.Since(start) > time.Second {
		t.Error("waited for a process that does not exist")
	}
	if os.Getenv(waitPIDEnv) != "" {
		t.Error("the variable was not cleared")
	}
}

func TestWaitForPreviousGivesUpAfterTheTimeout(t *testing.T) {
	t.Setenv(waitPIDEnv, strconv.Itoa(os.Getpid()))
	start := time.Now()
	WaitForPrevious(clock.New(), 200*time.Millisecond)
	if elapsed := time.Since(start); elapsed < 200*time.Millisecond || elapsed > 2*time.Second {
		t.Errorf("waited %v", elapsed)
	}
}

func TestWritable(t *testing.T) {
	dir := t.TempDir()
	if !writable(dir) {
		t.Error("temp dir is not writable")
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 0 {
		t.Errorf("writable left files: %v", entries)
	}
	if writable(dir + "/missing") {
		t.Error("a missing dir is writable")
	}
}
