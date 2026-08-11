package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"runtime/debug"

	enbucli "github.com/enbu-net/enbu/cli"
	"github.com/enbu-net/enbu/pkg/apperr"
)

var Version string

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	app := enbucli.New(getVersion())
	if err := app.ExecuteContext(ctx); err != nil {
		err = enbucli.NormalizeExecutionError(err)
		log.SetFlags(0)
		enbucli.RenderExecutionError(app, err, os.Args[1:])
		os.Exit(apperr.ExitCode(err))
	}
}

func getVersion() string {
	if Version != "" {
		return Version
	}

	if info, ok := debug.ReadBuildInfo(); ok {
		if info.Main.Version != "(devel)" {
			return info.Main.Version
		}

		if v, ok := getVCSBuildVersion(info); ok {
			return v
		}
	}

	return "(unset)"
}

func getVCSBuildVersion(info *debug.BuildInfo) (string, bool) {
	var (
		revision string
		dirty    string
	)

	for _, v := range info.Settings {
		switch v.Key {
		case "vcs.revision":
			revision = v.Value
		case "vcs.modified":
			if v.Value == "true" {
				dirty = " (dirty)"
			}
		}
	}

	if revision == "" {
		return "", false
	}

	return revision + dirty, true
}
