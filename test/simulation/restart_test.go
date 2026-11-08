package simulation

import (
	"context"
	"testing"

	"github.com/enbu-net/enbu/pkg/config"
)

func TestRestartReconstructsProcessDependenciesFromDurableFixtures(t *testing.T) {
	tape, err := Prepare(99, revision(t), Plan{Devices: 3})
	if err != nil {
		t.Fatal(err)
	}
	w, err := NewWorld(t.TempDir(), tape, 3)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := w.Bootstrap(ctx); err != nil {
		t.Fatal(err)
	}
	a := w.Devices[1].App
	if err := a.AddSecret(ctx, "default", "DURABLE", "value"); err != nil {
		t.Fatal(err)
	}
	w.Model["default"]["DURABLE"] = "value"
	if err := a.CreateEnvironment("personal"); err != nil {
		t.Fatal(err)
	}
	if err := w.Share(1); err != nil {
		t.Fatal(err)
	}
	w.Model["personal"] = map[string]string{}
	if err := a.SwitchEnvironment("personal"); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.LoadProjectFrom(a.RepositoryDir)
	if err != nil {
		t.Fatal(err)
	}
	keys := w.Devices[1].Keys
	pending, _, _, err := keys.CreatePending(cfg.WorkspaceID)
	if err != nil {
		t.Fatal(err)
	}
	recipient := pending.Recipient().String()
	_ = pending.Close()
	oldRuntime := a.Runtime
	a.AcceptNewGenesis = true
	a.Runtime.NewID = func() string { return "process-only-poison" }
	a.Runtime.Encrypt = func([]byte, []string) ([]byte, error) {
		t.Fatal("old process encryption survived restart")
		return nil, nil
	}
	w.Restart(1)
	fresh := w.Devices[1].App
	if fresh == a || fresh.Runtime == oldRuntime || w.Devices[1].Keys == keys || fresh.AcceptNewGenesis {
		t.Fatal("process-owned state survived restart")
	}
	if fresh.Runtime.NewID() == "process-only-poison" {
		t.Fatal("old Runtime callback survived restart")
	}
	if current, err := fresh.CurrentEnvironment(); err != nil || current != "personal" {
		t.Fatalf("personal selection lost: %s %v", current, err)
	}
	info, err := w.Devices[1].Keys.PendingInfo(cfg.WorkspaceID)
	if err != nil || info.Recipient != recipient {
		t.Fatalf("durable pending key lost: %+v %v", info, err)
	}
	if err := fresh.AddSecret(ctx, "default", "AFTER_RESTART", "new process"); err != nil {
		t.Fatal(err)
	}
	w.Model["default"]["AFTER_RESTART"] = "new process"
	if err := w.Check(ctx, "default"); err != nil {
		t.Fatal(err)
	}
}
