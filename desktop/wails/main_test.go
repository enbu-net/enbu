package main

import (
	"bytes"
	"log/slog"
	"os"
	"path/filepath"
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
	if got := singleInstance("linux", env(nil), "/home/u/.local/share/enbu", "/home/u/.local/share/enbu", onSecond); got != nil {
		t.Fatalf("singleInstance() without a session bus = %+v, want nil", got)
	}
	bus := map[string]string{"DBUS_SESSION_BUS_ADDRESS": "unix:path=/run/user/1000/bus"}
	if got := singleInstance("linux", env(bus), "/home/u/.local/share/enbu", "/home/u/.local/share/enbu", onSecond); got == nil || got.UniqueID != "net.enbu.desktop" {
		t.Fatalf("singleInstance() with a session bus = %+v", got)
	}
	for _, goos := range []string{"darwin", "windows"} {
		if got := singleInstance(goos, env(nil), "/home/u/.local/share/enbu", "/home/u/.local/share/enbu", onSecond); got == nil {
			t.Fatalf("singleInstance(%q) = nil, want options", goos)
		}
	}
}

func TestSingleInstanceIDFollowsTheDataDirectory(t *testing.T) {
	root := t.TempDir()
	def := filepath.Join(root, "home", ".local", "share", "enbu")
	if err := os.MkdirAll(def, 0o700); err != nil {
		t.Fatal(err)
	}
	if got := singleInstanceID(def, def); got != desktopID {
		t.Fatalf("singleInstanceID() for the default directory = %q, want %q", got, desktopID)
	}
	// XDG_DATA_HOME naming the default directory, by another spelling or
	// through a symlink, is still the default app.
	if got := singleInstanceID(def+string(filepath.Separator), def); got != desktopID {
		t.Fatalf("singleInstanceID() for the default directory with a trailing separator = %q", got)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(def, link); err == nil {
		if got := singleInstanceID(link, def); got != desktopID {
			t.Fatalf("singleInstanceID() through a symlink to the default directory = %q, want %q", got, desktopID)
		}
	}

	a := singleInstanceID(filepath.Join(root, "a", "enbu"), def)
	b := singleInstanceID(filepath.Join(root, "b", "enbu"), def)
	if a == desktopID || b == desktopID || a == b {
		t.Fatalf("singleInstanceID() for two data directories = %q and %q, want two IDs apart from %q", a, b, desktopID)
	}
	if again := singleInstanceID(filepath.Join(root, "a", "enbu")+string(filepath.Separator), def); again != a {
		t.Fatalf("singleInstanceID() for the same data directory = %q, then %q", a, again)
	}
	if !strings.HasPrefix(a, desktopID+".") {
		t.Fatalf("singleInstanceID() = %q, want the %q prefix", a, desktopID)
	}
	for _, element := range strings.Split(a, ".") {
		if element == "" || element[0] >= '0' && element[0] <= '9' {
			t.Fatalf("singleInstanceID() = %q is not a valid D-Bus name", a)
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
