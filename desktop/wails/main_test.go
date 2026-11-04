package main

import (
	"bytes"
	"log/slog"
	"reflect"
	"strings"
	"testing"

	"github.com/wailsapp/wails/v3/pkg/application"
)

type fakeWindow struct {
	calls []string
}

func (w *fakeWindow) Show() application.Window {
	w.calls = append(w.calls, "show")
	return nil
}

func (w *fakeWindow) UnMinimise() { w.calls = append(w.calls, "unminimise") }

func (w *fakeWindow) Focus() { w.calls = append(w.calls, "focus") }

func TestActivate(t *testing.T) {
	w := &fakeWindow{}
	activate(w)
	want := []string{"show", "unminimise", "focus"}
	if !reflect.DeepEqual(w.calls, want) {
		t.Fatalf("activate() calls = %v, want %v", w.calls, want)
	}
}

func TestSingleInstanceNeedsSessionBusOnLinux(t *testing.T) {
	env := func(vars map[string]string) func(string) string {
		return func(name string) string { return vars[name] }
	}
	onSecond := func(application.SecondInstanceData) {}
	if got := singleInstance("linux", env(nil), onSecond); got != nil {
		t.Fatalf("singleInstance() without a session bus = %+v, want nil", got)
	}
	bus := map[string]string{"DBUS_SESSION_BUS_ADDRESS": "unix:path=/run/user/1000/bus"}
	if got := singleInstance("linux", env(bus), onSecond); got == nil || got.UniqueID != "net.enbu.desktop" {
		t.Fatalf("singleInstance() with a session bus = %+v", got)
	}
	for _, goos := range []string{"darwin", "windows"} {
		if got := singleInstance(goos, env(nil), onSecond); got == nil {
			t.Fatalf("singleInstance(%q) = nil, want options", goos)
		}
	}
}

func TestWailsLoggerDropsDebugRecords(t *testing.T) {
	var buf bytes.Buffer
	app := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	logger := wailsLogger(app).With("component", "wails")

	logger.Debug("Binding call complete:", "args", `["default","TOKEN","s3cret"]`)
	logger.Info("started")

	out := buf.String()
	if strings.Contains(out, "s3cret") {
		t.Fatalf("debug record was logged: %s", out)
	}
	if !strings.Contains(out, "started") || !strings.Contains(out, "component=wails") {
		t.Fatalf("info record missing: %s", out)
	}
}
