package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"runtime/debug"

	"github.com/enbu-net/enbu/app"
	enbucli "github.com/enbu-net/enbu/cli"
	"github.com/enbu-net/enbu/pkg/apperr"
)

var (
	Version string
	// registryHost stays private and is overridden only in E2E builds so the
	// production CLI keeps its fixed registry behavior.
	registryHost string
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	service := app.New()
	service.RegistryHost = registryHost
	command := enbucli.NewWithApp(getVersion(), service)
	if err := command.ExecuteContext(ctx); err != nil {
		err = apperr.Normalize(err)
		log.SetFlags(0)
		enbucli.RenderExecutionError(command, err, os.Args[1:])
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
