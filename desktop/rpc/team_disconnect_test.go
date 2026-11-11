package rpc

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/enbu-net/enbu/app"
	"github.com/enbu-net/enbu/desktop"
	"github.com/enbu-net/enbu/pkg/config"
	gitprovider "github.com/enbu-net/enbu/pkg/provider/git"
	"github.com/enbu-net/enbu/pkg/storage"
	"github.com/enbu-net/enbu/pkg/storage/storagetest"
	"github.com/enbu-net/enbu/pkg/wsp"
	"github.com/enbu-net/enbu/test/simulation"
)

type rpcFolderInspector struct{ inspect func(string) }

func (g rpcFolderInspector) Inspect(_ context.Context, path string) (gitprovider.Repository, error) {
	if g.inspect != nil {
		g.inspect(path)
	}
	return gitprovider.Repository{Root: path}, nil
}

func TestTeamPublicationSurvivesRPCDisconnect(t *testing.T) {
	for _, op := range []string{"edit", "remove"} {
		for _, committed := range []bool{false, true} {
			for _, profile := range []string{"", "frozen", "backward", "skewed"} {
				t.Run(fmt.Sprintf("%s/committed-%t/%s", op, committed, profile), func(t *testing.T) {
					t.Setenv("XDG_DATA_HOME", t.TempDir())
					ctx := wsp.WithSerialHeadReads(t.Context())
					world, err := simulation.NewWorld(t.TempDir(), simulation.NewTape(89, "rpc-disconnect"), 3)
					if err != nil {
						t.Fatal(err)
					}
					world.Clock = profile
					if err := world.Bootstrap(ctx); err != nil {
						t.Fatal(err)
					}
					const initial = "private-initial-canary"
					const requested = "private-unacknowledged-canary"
					const peer = "private-peer-canary"
					a := world.Devices[0].App
					if err := a.AddSecret(ctx, "default", "BASE", initial); err != nil {
						t.Fatal(err)
					}
					world.Model["default"] = map[string]string{"BASE": initial}
					if err := world.Check(ctx, "default"); err != nil {
						t.Fatal(err)
					}
					watchdog, stop := context.WithTimeout(ctx, 10*time.Second)
					defer stop()
					entered, selecting := make(chan struct{}), make(chan struct{})
					other := t.TempDir()
					a.Git = rpcFolderInspector{inspect: func(path string) {
						if path == other {
							close(selecting)
						}
					}}
					originalDir := a.RepositoryDir
					core := desktop.NewService(a)
					if _, err := core.SelectRepository(a.RepositoryDir); err != nil {
						t.Fatal(err)
					}
					base := world.Devices[0].Store.Store
					kind := storage.KindState
					if op == "remove" {
						kind = storage.KindControl
					}
					blocked := false
					world.Devices[0].Store.Store = storagetest.Wrap(base, storagetest.Hooks{Publish: func(callCtx context.Context, next storage.Store, object storage.Object) error {
						if object.Kind != kind || blocked {
							return next.Publish(callCtx, object)
						}
						blocked = true
						if committed {
							if err := next.Publish(callCtx, object); err != nil {
								return err
							}
						}
						close(entered)
						<-callCtx.Done()
						return callCtx.Err()
					}})
					reqR, reqW := io.Pipe()
					defer func() { _ = reqW.Close(); _ = reqR.Close() }()
					var output bytes.Buffer // Server serializes all responses/events.
					done := make(chan error, 1)
					go func() { done <- NewServer(core).Serve(watchdog, reqR, &output) }()
					send := func(id int, method string, params ...any) {
						t.Helper()
						data, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": id, "method": method, "params": params})
						if err != nil {
							t.Fatal(err)
						}
						if _, err := reqW.Write(append(data, '\n')); err != nil {
							t.Fatal(err)
						}
					}
					if op == "edit" {
						send(1, "EditSecret", "default", "BASE", requested)
					} else {
						send(1, "RemoveMember", world.Devices[1].ID)
					}
					select {
					case <-entered:
					case <-watchdog.Done():
						t.Fatal("RPC publication boundary not reached")
					}
					// The real teammate commits while the RPC writer is paused.
					if err := world.Devices[2].App.AddSecret(ctx, "default", "PEER", peer); err != nil {
						t.Fatal(err)
					}
					send(2, "SelectRepository", other)
					select {
					case <-selecting:
					case <-watchdog.Done():
						t.Fatal("queued workspace switch not reached")
					}
					_ = reqW.Close() // Editor connection disappears with calls in flight.
					select {
					case err := <-done:
						if err != nil {
							t.Fatal(err)
						}
					case <-watchdog.Done():
						t.Fatal("RPC did not finish after disconnect")
					}
					world.Devices[0].Store.Store = base
					gui, err := config.LoadGUI()
					if err != nil || gui.SelectedRepo != originalDir {
						t.Errorf("canceled switch changed persistent selection: %+v err=%v", gui, err)
					}
					for _, value := range []string{initial, requested, peer} {
						if strings.Contains(output.String(), value) {
							t.Error("RPC error/event output disclosed a secret canary")
						}
					}
					world.Restart(0)
					a = world.Devices[0].App
					world.Model["default"]["PEER"] = peer
					if op == "edit" && committed {
						world.Model["default"]["BASE"] = requested
					}
					if op == "remove" && committed {
						members, err := a.ListMembers(ctx)
						if err != nil || len(members) != 2 {
							t.Fatalf("committed removal was lost: %+v err=%v", members, err)
						}
						if _, err := world.Devices[1].App.InitializeRepository(ctx, app.InitOptions{}); err != nil {
							t.Fatal(err)
						}
						if err := a.ApproveMember(ctx, world.Devices[1].ID); err != nil {
							t.Fatal(err)
						}
					}
					if err := world.Check(ctx, "default"); err != nil {
						t.Fatal(err)
					}
					if err := a.EditSecret(ctx, "default", "BASE", "after-reconnect"); err != nil {
						t.Fatal(err)
					}
					world.Model["default"]["BASE"] = "after-reconnect"
					if err := world.Check(ctx, "default"); err != nil {
						t.Fatal(err)
					}
					got, err := world.Devices[2].App.ListSecrets(ctx, "default")
					if err != nil || !reflect.DeepEqual(got, world.Model["default"]) {
						t.Fatalf("teammate update lost after reconnect: %v", err)
					}
				})
			}
		}
	}
}
