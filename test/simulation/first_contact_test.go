package simulation

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestFirstContactThroughSymlink(t *testing.T) {
	t.Parallel()
	for _, cache := range []string{"warm", "cold"} {
		t.Run(cache, func(t *testing.T) {
			t.Parallel()
			real := t.TempDir()
			alias := filepath.Join(t.TempDir(), "world")
			if err := os.Symlink(real, alias); err != nil {
				t.Skipf("directory symlinks unavailable: %v", err)
			}
			tape, err := Prepare(367, revision(t), Plan{Devices: 5, Clock: "frozen", Scenario: "first-contact-" + cache})
			if err != nil {
				t.Fatal(err)
			}
			if err := Execute(context.Background(), tape, alias); err != nil {
				t.Fatal(err)
			}
			replay := &Tape{Recording: tape.Recording, Replay: true}
			if err := Execute(context.Background(), replay, t.TempDir()); err != nil {
				t.Fatal(err)
			}
			if err := replay.Finish(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestFirstContactSmoke(t *testing.T) {
	t.Parallel()
	shardCase(t)
	exercise(t, 367, Plan{Devices: 5, Clock: "frozen", Scenario: "first-contact-cold"})
}

func TestFirstContactClocks(t *testing.T) {
	t.Parallel()
	exploration(t)
	for _, devices := range []int{5, 6, 11} {
		for _, clock := range []string{"", "frozen", "backward", "skewed"} {
			for _, cache := range []string{"warm", "cold"} {
				t.Run(fmt.Sprintf("devices-%d/%s/%s", devices, clock, cache), func(t *testing.T) {
					t.Parallel()
					shardCase(t)
					exercise(t, 367, Plan{Devices: devices, Clock: clock, Scenario: "first-contact-" + cache})
				})
			}
		}
	}
}
