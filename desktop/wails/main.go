package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/enbu-net/enbu/app"
	"github.com/enbu-net/enbu/assets"
	"github.com/enbu-net/enbu/desktop"
	"github.com/enbu-net/enbu/web"
	"github.com/wailsapp/wails/v3/pkg/application"
	"github.com/wailsapp/wails/v3/pkg/events"
)

var Version string

// Typed events let the binding generator emit their payload types for the
// frontend.
func init() {
	application.RegisterEvent[app.ProgressStep](desktop.EventProgress)
	application.RegisterEvent[string](desktop.EventProgressMessage)
	application.RegisterEvent[desktop.ConflictRetry](desktop.EventConflictRetry)
}

// singleInstance keeps one app running per user. On Linux Wails finds the
// running app over the D-Bus session bus and stops with a fatal error when
// there is none, so without a session bus a second window is the lesser harm.
func singleInstance(goos string, getenv func(string) string, onSecond func(application.SecondInstanceData)) *application.SingleInstanceOptions {
	if goos == "linux" && getenv("DBUS_SESSION_BUS_ADDRESS") == "" {
		slog.Warn("no D-Bus session bus; more than one enbu window may open")
		return nil
	}
	return &application.SingleInstanceOptions{
		UniqueID:               "net.enbu.desktop",
		OnSecondInstanceLaunch: onSecond,
	}
}

func setupLogger() *os.File {
	dir, err := os.UserCacheDir()
	if err != nil {
		dir = os.TempDir()
	}
	dir = filepath.Join(dir, "enbu")
	_ = os.MkdirAll(dir, 0o700)
	name := filepath.Join(dir, fmt.Sprintf("enbu-%s.log", time.Now().Format("20060102-150405")))
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
	logFile := setupLogger()
	if logFile != nil {
		defer func() {
			_ = logFile.Close()
		}()
	}
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

	core := desktop.NewService(app.New())
	core.AppVersion = Version
	core.Start(ctx)

	var mainWindow *application.WebviewWindow
	wailsApp := application.New(application.Options{
		Name:        "enbu",
		Description: "Keyless .env management",
		Icon:        assets.Icon,
		Logger:      wailsLogger(slog.Default()),
		Services: []application.Service{
			application.NewService(&DesktopService{core: core}),
		},
		MarshalError: marshalError,
		Assets: application.AssetOptions{
			Handler: application.AssetFileServerFS(web.FrontendFS()),
		},
		SingleInstance: singleInstance(runtime.GOOS, os.Getenv, func(data application.SecondInstanceData) {
			slog.Info("second instance launch", "args", data.Args, "cwd", data.WorkingDir)
			if mainWindow != nil {
				activate(mainWindow)
			}
		}),
		Mac: application.MacOptions{
			ApplicationShouldTerminateAfterLastWindowClosed: true,
		},
		Linux: application.LinuxOptions{
			ProgramName: "enbu",
		},
		OnShutdown: cancel,
	})

	core.SetDirectoryPicker(func(context.Context) (string, error) {
		return wailsApp.Dialog.OpenFile().
			SetTitle("Select Git repository").
			CanChooseFiles(false).
			CanChooseDirectories(true).
			CanCreateDirectories(true).
			PromptForSingleSelection()
	})
	core.SetBrowserOpener(wailsApp.Browser.OpenURL)
	core.SetEventEmitter(func(name string, data any) {
		wailsApp.Event.Emit(name, data)
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
