package process

import (
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func dumpable() int {
	v, err := unix.PrctlRetInt(unix.PR_GET_DUMPABLE, 0, 0, 0, 0)
	if err != nil {
		return -1
	}
	return v
}

// TestHardenHelperProcess reports whether it is dumpable. With
// ENBU_TEST_HARDEN it hardens itself first, then starts itself again unhardened
// to show what a command started by enbu run gets.
func TestHardenHelperProcess(t *testing.T) {
	switch os.Getenv("ENBU_TEST_HARDEN_HELPER") {
	case "report":
		_, _ = os.Stdout.WriteString(strconv.Itoa(dumpable()))
		os.Exit(0)
	case "harden":
		if err := Harden(); err != nil {
			os.Exit(2)
		}
		child := exec.Command(os.Args[0], "-test.run=^TestHardenHelperProcess$")
		child.Env = append(os.Environ(), "ENBU_TEST_HARDEN_HELPER=report")
		out, err := child.Output()
		if err != nil {
			os.Exit(3)
		}
		_, _ = os.Stdout.WriteString(strconv.Itoa(dumpable()) + " " + string(out))
		os.Exit(0)
	}
}

// Harden makes enbu not dumpable, and execve makes the command dumpable again.
func TestHardenStopsDumpingButNotTheCommand(t *testing.T) {
	cmd := exec.Command(os.Args[0], "-test.run=^TestHardenHelperProcess$")
	cmd.Env = append(os.Environ(), "ENBU_TEST_HARDEN_HELPER=harden")
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("helper: %v", err)
	}
	if got := strings.TrimSpace(string(out)); got != "0 1" {
		t.Fatalf("dumpable of enbu and its command = %q, want \"0 1\"", got)
	}
}
