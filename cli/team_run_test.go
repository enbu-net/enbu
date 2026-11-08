package cli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/enbu-net/enbu/pkg/apperr"
	"github.com/enbu-net/enbu/pkg/wsp"
	"github.com/enbu-net/enbu/test/simulation"
)

func TestTeamRunChild(t *testing.T) {
	if os.Getenv("ENBU_TEAM_RUN_CHILD") != "1" {
		return
	}
	var signal [1]byte
	if _, err := io.ReadFull(os.Stdin, signal[:]); err != nil {
		os.Exit(2)
	}
	a, b := os.Getenv("TEAM_A"), os.Getenv("TEAM_B")
	fmt.Printf("SNAPSHOT=%x\nA=%s\n", sha256.Sum256([]byte(a+"\x00"+b)), a)
	_, _ = fmt.Fprintf(os.Stderr, "B=%s\n", b)
	os.Exit(0)
}

type teamRunGate struct {
	once    sync.Once
	entered chan struct{}
	release chan struct{}
	read    bool
}

func (g *teamRunGate) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if g.read {
		return 0, io.EOF
	}
	g.once.Do(func() { close(g.entered) })
	<-g.release
	g.read = true
	p[0] = 1
	return 1, nil
}

func TestRunSnapshotDuringTeamChanges(t *testing.T) {
	for _, change := range []string{"edit", "remove", "upgrade"} {
		for _, profile := range []string{"", "frozen", "backward", "skewed"} {
			for _, unmasked := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%s/unmasked-%t", change, profile, unmasked), func(t *testing.T) {
					t.Setenv("ENBU_TEAM_RUN_CHILD", "1")
					ctx := wsp.WithSerialHeadReads(t.Context())
					world, err := simulation.NewWorld(t.TempDir(), simulation.NewTape(97, "run-team-change"), 3)
					if err != nil {
						t.Fatal(err)
					}
					world.Clock = profile
					if err := world.Bootstrap(ctx); err != nil {
						t.Fatal(err)
					}
					before := map[string]string{"TEAM_A": "old-private-canary-a", "TEAM_B": "old-private-canary-b"}
					after := map[string]string{"TEAM_A": "new-private-canary-a", "TEAM_B": "new-private-canary-b"}
					admin := world.Devices[0].App
					if _, err := admin.ImportSecrets(ctx, "default", before, true); err != nil {
						t.Fatal(err)
					}
					world.Model["default"] = before
					if err := world.Check(ctx, "default"); err != nil {
						t.Fatal(err)
					}
					gate := &teamRunGate{entered: make(chan struct{}), release: make(chan struct{})}
					var release sync.Once
					defer release.Do(func() { close(gate.release) })
					cmd := newRunCommand(world.Devices[1].App)
					cmd.SetContext(ctx)
					cmd.SetIn(gate)
					var stdout, stderr bytes.Buffer
					cmd.SetOut(&stdout)
					cmd.SetErr(&stderr)
					args := []string{"--env", "default"}
					if unmasked {
						args = append(args, "--no-masking")
					}
					cmd.SetArgs(append(args, "--", os.Args[0], "-test.run=^TestTeamRunChild$"))
					done := make(chan error, 1)
					go func() { done <- cmd.Execute() }()
					watchdog, stop := context.WithTimeout(ctx, 10*time.Second)
					defer stop()
					select {
					case <-gate.entered:
						// exec starts stdin copying only after freezing child.Env.
					case err := <-done:
						t.Fatalf("run stopped before child input: %v", err)
					case <-watchdog.Done():
						t.Fatal("child launch did not reach stdin")
					}
					if _, err := admin.ImportSecrets(ctx, "default", after, true); err != nil {
						t.Fatal(err)
					}
					world.Model["default"] = after
					switch change {
					case "remove":
						if err := admin.RemoveMember(ctx, world.Devices[1].ID); err != nil {
							t.Fatal(err)
						}
					case "upgrade":
						if _, err := world.Devices[1].App.UpgradeIdentity(ctx); err != nil {
							t.Fatal(err)
						}
						if err := admin.ApproveMember(ctx, world.Devices[1].ID); err != nil {
							t.Fatal(err)
						}
					}
					release.Do(func() { close(gate.release) })
					select {
					case err := <-done:
						if err != nil {
							t.Fatal(err)
						}
					case <-watchdog.Done():
						t.Fatal("child did not finish")
					}
					// Revocation cannot retract plaintext already obtained. Require
					// the original complete snapshot, never mixed old/new values.
					digestLine := fmt.Sprintf("SNAPSHOT=%x\n", sha256.Sum256([]byte(before["TEAM_A"]+"\x00"+before["TEAM_B"])))
					wantA, wantB := "<concealed by enbu>", "<concealed by enbu>"
					if unmasked {
						wantA, wantB = before["TEAM_A"], before["TEAM_B"]
					}
					if stdout.String() != digestLine+"A="+wantA+"\n" || stderr.String() != "B="+wantB+"\n" {
						t.Fatal("child snapshot or stdout/stderr masking differed from the expected state")
					}
					if change == "remove" {
						denied := newRunCommand(world.Devices[1].App)
						denied.SetContext(ctx)
						var output bytes.Buffer
						denied.SetOut(&output)
						denied.SetErr(&output)
						denied.SetArgs([]string{"--env", "default", "--", os.Args[0], "-test.run=^TestTeamRunChild$"})
						if err := denied.Execute(); !apperr.Is(err, apperr.CodeNotMember) {
							t.Fatalf("removed member started a new export: %v", err)
						}
						if strings.Contains(output.String(), "SNAPSHOT=") {
							t.Fatal("denied export launched a child")
						}
						if _, err := world.Devices[1].App.InitializeRepository(ctx); err != nil {
							t.Fatal(err)
						}
						if err := admin.ApproveMember(ctx, world.Devices[1].ID); err != nil {
							t.Fatal(err)
						}
					}
					world.Restart(1)
					if err := world.Check(ctx, "default"); err != nil {
						t.Fatal(err)
					}
				})
			}
		}
	}
}
