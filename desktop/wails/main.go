package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/enbu-net/enbu/pkg/clock"

	"github.com/enbu-net/enbu/app"
	"github.com/enbu-net/enbu/assets"
	"github.com/enbu-net/enbu/desktop"
	"github.com/enbu-net/enbu/pkg/config"
	"github.com/enbu-net/enbu/pkg/process"
	"github.com/enbu-net/enbu/pkg/selfupdate"
	"github.com/enbu-net/enbu/web"
	"github.com/wailsapp/wails/v3/pkg/application"
	"github.com/wailsapp/wails/v3/pkg/events"
)

var Version string

// desktopID is the app's GTK application ID on Linux, and the name of its
// desktop entry and icon. Wayland matches a window to the desktop entry of the
// same name, which gives the window its icon. GLib also uses it as the program
// name, so WebKit keeps its own data under it, apart from enbu's data
// directory.
const desktopID = "net.enbu.desktop"

// Typed events let the binding generator emit their payload types for the
// frontend.
func init() {
	application.RegisterEvent[app.ProgressStep](desktop.EventProgress)
	application.RegisterEvent[string](desktop.EventProgressMessage)
	application.RegisterEvent[desktop.ConflictRetry](desktop.EventConflictRetry)
}

// singleInstance keeps one app running per user and data directory. On Linux
// Wails finds the running app over the D-Bus session bus and stops with a fatal
// error when there is none, so without a session bus a second window is the
// lesser harm.
func singleInstance(goos string, getenv func(string) string, dataDir, defaultDir string, onSecond func(application.SecondInstanceData)) *application.SingleInstanceOptions {
	if goos == "linux" && getenv("DBUS_SESSION_BUS_ADDRESS") == "" {
		slog.Warn("no D-Bus session bus; more than one enbu window may open")
		return nil
	}
	return &application.SingleInstanceOptions{
		UniqueID:               singleInstanceID(dataDir, defaultDir),
		OnSecondInstanceLaunch: onSecond,
	}
}

// singleInstanceID is desktopID for the default data directory, and one
// derived from the directory for any other: each data directory holds its own
// identity and local state, so an app started with another one is another
// device and runs beside the first. Paths are compared after resolving
// symlinks, so two spellings of one directory share one app. The suffix starts
// with a letter because D-Bus names allow no leading digit.
func singleInstanceID(dataDir, defaultDir string) string {
	dir := resolvedDir(dataDir)
	if dir == resolvedDir(defaultDir) {
		return desktopID
	}
	sum := sha256.Sum256([]byte(dir))
	return desktopID + ".d" + hex.EncodeToString(sum[:6])
}

// resolvedDir is dir with symlinks resolved. Before the directory exists, its
// nearest existing ancestor is resolved, so the ID does not change when the
// app creates it.
func resolvedDir(dir string) string {
	dir = filepath.Clean(dir)
	var missing []string
	for {
		if resolved, err := filepath.EvalSymlinks(dir); err == nil {
			return filepath.Join(append([]string{resolved}, missing...)...)
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return filepath.Join(append([]string{dir}, missing...)...)
		}
		missing = append([]string{filepath.Base(dir)}, missing...)
		dir = parent
	}
}

func setupLogger() *os.File {
	dir, err := os.UserCacheDir()
	if err != nil {
		dir = os.TempDir()
	}
	dir = filepath.Join(dir, "enbu")
	_ = os.MkdirAll(dir, 0o700)
	name := filepath.Join(dir, fmt.Sprintf("enbu-%s.log", clock.New().Now().Format("20060102-150405")))
	f, err := os.OpenFile(name, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil
	}
	h := slog.NewTextHandler(f, &slog.HandlerOptions{
		Level:     slog.LevelDebug,
		AddSource: true,
	})
	slog.SetDefault(slog.New(h))
	slog.Info("enbu desktop starting", "log", name)
	return f
}

// minLevel drops records below min, whatever the wrapped handler accepts.
type minLevel struct {
	slog.Handler
	min slog.Level
}

func (h minLevel) Enabled(ctx context.Context, level slog.Level) bool {
	return level >= h.min && h.Handler.Enabled(ctx, level)
}

func (h minLevel) WithAttrs(attrs []slog.Attr) slog.Handler {
	return minLevel{h.Handler.WithAttrs(attrs), h.min}
}

func (h minLevel) WithGroup(name string) slog.Handler {
	return minLevel{h.Handler.WithGroup(name), h.min}
}

// wailsLogger is the app's logger without debug records: at debug level Wails
// logs every binding call with its arguments and result, which include secret
// values.
func wailsLogger(logger *slog.Logger) *slog.Logger {
	return slog.New(minLevel{logger.Handler(), slog.LevelInfo})
}

// marshalError is the cause the frontend receives with a failed call: the
// AppError payload, never an internal cause.
func marshalError(err error) []byte {
	data, err := json.Marshal(desktop.ErrorPayload(err))
	if err != nil {
		return nil
	}
	return data
}

// window is the part of the main window that activation needs.
type window interface {
	Show() application.Window
	UnMinimise()
	Focus()
}

// activate brings the window to the front when a second launch or an enbu://
// link reaches the running app.
func activate(w window) {
	w.Show()
	w.UnMinimise()
	w.Focus()
}

func main() {
	// Before anything decrypts: keeps same-user processes out of enbu's memory.
	_ = process.Harden()
	logFile := setupLogger()
	if logFile != nil {
		defer func() {
			_ = logFile.Close()
		}()
	}
	// After an update, the app that installed it may still hold the
	// single-instance lock for a moment.
	selfupdate.WaitForPrevious(clock.New(), 15*time.Second)
	if err := registerProtocolHandler(); err != nil {
		slog.Warn("registering enbu protocol handler", "err", err)
	}
	if err := run(); err != nil {
		slog.Error("desktop app failed", "err", err)
		os.Exit(1)
	}
}

func run() error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	core := desktop.NewService(app.New(clock.New()))
	core.AppVersion = Version

	var mainWindow *application.WebviewWindow
	wailsApp := application.New(application.Options{
		Name:        "enbu",
		Description: "Keyless .env management",
		Icon:        assets.Icon,
		Logger:      wailsLogger(slog.Default()),
		Services: []application.Service{
			application.NewService(core),
		},
		MarshalError: marshalError,
		Assets: application.AssetOptions{
			Handler: application.AssetFileServerFS(web.FrontendFS()),
		},
		SingleInstance: singleInstance(runtime.GOOS, os.Getenv, config.DataDir(), config.DefaultDataDir(), func(data application.SecondInstanceData) {
			slog.Info("second instance launch", "args", data.Args, "cwd", data.WorkingDir)
			if mainWindow != nil {
				activate(mainWindow)
			}
		}),
		Mac: application.MacOptions{
			ApplicationShouldTerminateAfterLastWindowClosed: true,
		},
		Linux: application.LinuxOptions{
			ApplicationID: desktopID,
		},
		OnShutdown: cancel,
	})

	desktop.Attach(ctx, core, desktop.Host{
		PickDirectory: func(context.Context) (string, error) {
			return wailsApp.Dialog.OpenFile().
				SetTitle("Select Git repository").
				CanChooseFiles(false).
				CanChooseDirectories(true).
				CanCreateDirectories(true).
				PromptForSingleSelection()
		},
		OpenURL: wailsApp.Browser.OpenURL,
		Emit: func(name string, data any) {
			wailsApp.Event.Emit(name, data)
		},
		Updater: newUpdater(Version, wailsApp.Quit),
	})

	mainWindow = wailsApp.Window.NewWithOptions(application.WebviewWindowOptions{
		Title:  "enbu",
		Width:  1100,
		Height: 760,
		// Wide enough for the repository sidebar, which shows from 768px.
		MinWidth:         800,
		MinHeight:        520,
		URL:              "/",
		BackgroundColour: application.NewRGB(0xfa, 0xfa, 0xfa),
	})
	wailsApp.Event.OnApplicationEvent(events.Common.ApplicationLaunchedWithUrl, func(*application.ApplicationEvent) {
		slog.Info("URL opened")
		activate(mainWindow)
	})

	return wailsApp.Run()
}
