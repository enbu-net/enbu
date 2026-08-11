package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/enbu-net/enbu/assets"
	"github.com/enbu-net/enbu/desktop"
	"github.com/enbu-net/enbu/web"
	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/logger"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
	"github.com/wailsapp/wails/v2/pkg/options/linux"
	"github.com/wailsapp/wails/v2/pkg/options/mac"
	"github.com/wailsapp/wails/v2/pkg/runtime"
)

var Version string

type slogWailsLogger struct{}

type windowActions struct {
	show       func(context.Context)
	unminimise func(context.Context)
	center     func(context.Context)
}

var wailsWindowActions = windowActions{
	show:       runtime.WindowShow,
	unminimise: runtime.WindowUnminimise,
	center:     runtime.WindowCenter,
}

func (slogWailsLogger) Print(message string) { slog.Debug("wails print", "message", message) }
func (slogWailsLogger) Trace(message string) { slog.Debug("wails trace", "message", message) }
func (slogWailsLogger) Debug(message string) { slog.Debug("wails debug", "message", message) }
func (slogWailsLogger) Info(message string)  { slog.Info("wails info", "message", message) }
func (slogWailsLogger) Warning(message string) {
	slog.Warn("wails warning", "message", message)
}
func (slogWailsLogger) Error(message string) { slog.Error("wails error", "message", message) }
func (slogWailsLogger) Fatal(message string) { slog.Error("wails fatal", "message", message) }

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

func showWindow(ctx context.Context, actions windowActions) {
	if ctx == nil {
		return
	}
	actions.show(ctx)
	actions.unminimise(ctx)
	actions.center(ctx)
}

func activationHandlers(contextProvider func() context.Context, activate func(context.Context)) (func(options.SecondInstanceData), func(string)) {
	return func(data options.SecondInstanceData) {
			slog.Info("second instance launch", "args", data.Args, "cwd", data.WorkingDirectory)
			activate(contextProvider())
		}, func(_ string) {
			slog.Info("URL opened")
			activate(contextProvider())
		}
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

	core := desktop.NewService(Version)
	service := &DesktopService{service: core}
	onSecondInstanceLaunch, onURLOpen := activationHandlers(
		core.Context,
		func(ctx context.Context) { showWindow(ctx, wailsWindowActions) },
	)
	core.SetDirectoryPicker(func(ctx context.Context) (string, error) {
		slog.Debug("OpenDirectoryDialog called")
		return runtime.OpenDirectoryDialog(ctx, runtime.OpenDialogOptions{
			Title: "Select Git repository",
		})
	})
	core.SetFilePicker(func(ctx context.Context, title string) (string, error) {
		return runtime.OpenFileDialog(ctx, runtime.OpenDialogOptions{Title: title})
	})
	core.SetSavePicker(func(ctx context.Context, title string) (string, error) {
		return runtime.SaveFileDialog(ctx, runtime.SaveDialogOptions{Title: title})
	})

	if err := wails.Run(&options.App{
		Title:              "enbu",
		Width:              1100,
		Height:             760,
		Logger:             slogWailsLogger{},
		LogLevel:           logger.TRACE,
		LogLevelProduction: logger.TRACE,
		SingleInstanceLock: &options.SingleInstanceLock{
			UniqueId:               "net.enbu.desktop",
			OnSecondInstanceLaunch: onSecondInstanceLaunch,
		},
		AssetServer: &assetserver.Options{
			Assets: web.FrontendFS(),
		},
		Mac: &mac.Options{
			About: &mac.AboutInfo{
				Title: "enbu",
				Icon:  assets.Icon,
			},
			OnUrlOpen: onURLOpen,
		},
		Linux: &linux.Options{
			Icon:        assets.Icon,
			ProgramName: "enbu",
		},
		OnStartup: core.Startup,
		OnShutdown: func(ctx context.Context) {
			if err := core.Shutdown(ctx); err != nil {
				slog.Error("desktop shutdown failed", "err", err)
			}
		},
		OnDomReady: func(ctx context.Context) {
			slog.Info("Wails.OnDomReady called")
		},
		Bind: []interface{}{
			service,
		},
	}); err != nil {
		slog.Error("wails.Run failed", "err", err)
		os.Exit(1)
	}
}
