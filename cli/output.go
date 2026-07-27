package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/enbu-net/enbu/app"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

type successEnvelope struct {
	OK       bool     `json:"ok"`
	Data     any      `json:"data"`
	Warnings []string `json:"warnings"`
}

type errorEnvelope struct {
	OK    bool          `json:"ok"`
	Error errorResponse `json:"error"`
}

type errorResponse struct {
	Message string `json:"message"`
}

type helpResponse struct {
	Command     string            `json:"command"`
	Usage       string            `json:"usage"`
	Description string            `json:"description"`
	Commands    []commandResponse `json:"commands"`
	Flags       []flagResponse    `json:"flags"`
}

type commandResponse struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

type flagResponse struct {
	Name      string `json:"name"`
	Shorthand string `json:"shorthand,omitempty"`
	Usage     string `json:"usage"`
	Default   string `json:"default,omitempty"`
}

func jsonEnabled(cmd *cobra.Command) bool {
	flag := cmd.Root().PersistentFlags().Lookup("json")
	return flag != nil && flag.Value.String() == "true"
}

func writeJSON(cmd *cobra.Command, data any, warnings ...string) error {
	if warnings == nil {
		warnings = []string{}
	}
	return encodeJSON(cmd.OutOrStdout(), successEnvelope{
		OK:       true,
		Data:     data,
		Warnings: warnings,
	})
}

func writeErrorJSON(w io.Writer, err error) error {
	return encodeJSON(w, errorEnvelope{
		OK: false,
		Error: errorResponse{
			Message: err.Error(),
		},
	})
}

func encodeJSON(w io.Writer, value any) error {
	encoder := json.NewEncoder(w)
	encoder.SetEscapeHTML(false)
	return encoder.Encode(value)
}

func renderHelp(cmd *cobra.Command) error {
	if !jsonEnabled(cmd) {
		return cmd.Help()
	}
	return writeJSON(cmd, commandHelp(cmd))
}

func commandHelp(cmd *cobra.Command) helpResponse {
	commands := make([]commandResponse, 0)
	for _, sub := range cmd.Commands() {
		if !sub.IsAvailableCommand() || sub.IsAdditionalHelpTopicCommand() {
			continue
		}
		commands = append(commands, commandResponse{
			Name:        sub.Name(),
			Description: sub.Short,
		})
	}

	flags := make([]flagResponse, 0)
	seen := make(map[string]bool)
	addFlags := func(set *pflag.FlagSet) {
		set.VisitAll(func(flag *pflag.Flag) {
			if seen[flag.Name] {
				return
			}
			seen[flag.Name] = true
			flags = append(flags, flagResponse{
				Name:      flag.Name,
				Shorthand: flag.Shorthand,
				Usage:     flag.Usage,
				Default:   flag.DefValue,
			})
		})
	}
	addFlags(cmd.NonInheritedFlags())
	addFlags(cmd.InheritedFlags())

	return helpResponse{
		Command:     cmd.CommandPath(),
		Usage:       cmd.UseLine(),
		Description: cmd.Short,
		Commands:    commands,
		Flags:       flags,
	}
}

func humanPrintf(cmd *cobra.Command, format string, args ...any) {
	if !jsonEnabled(cmd) {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), format, args...)
	}
}

func humanErrorf(cmd *cobra.Command, format string, args ...any) {
	if !jsonEnabled(cmd) {
		_, _ = fmt.Fprintf(cmd.ErrOrStderr(), format, args...)
	}
}

func resolvedEnvironmentName(a *app.App, requested string) string {
	if requested != "" {
		return requested
	}
	current, err := a.CurrentEnvironment()
	if err != nil {
		return app.DefaultEnvironment
	}
	return current
}

func requestedJSON(cmd *cobra.Command, args []string) bool {
	// Find the target subcommand to know which flags consume a value.
	target, _, _ := cmd.Find(args)
	if target == nil {
		target = cmd
	}
	nonBoolFlags := make(map[string]bool)
	addNonBool := func(fs *pflag.FlagSet) {
		fs.VisitAll(func(f *pflag.Flag) {
			if f.Value.Type() != "bool" {
				nonBoolFlags[f.Name] = true
				if f.Shorthand != "" {
					nonBoolFlags[f.Shorthand] = true
				}
			}
		})
	}
	addNonBool(target.Flags())
	addNonBool(target.InheritedFlags())

	skipNext := false
	for _, arg := range args {
		if arg == "--" {
			break
		}
		if skipNext {
			skipNext = false
			continue
		}
		switch {
		case arg == "--json":
			return true
		case strings.HasPrefix(arg, "--json="):
			return strings.TrimPrefix(arg, "--json=") != "false"
		case strings.HasPrefix(arg, "--") && !strings.Contains(arg, "="):
			name := strings.TrimPrefix(arg, "--")
			if nonBoolFlags[name] {
				skipNext = true
			}
		case strings.HasPrefix(arg, "-") && len(arg) == 2:
			if nonBoolFlags[arg[1:]] {
				skipNext = true
			}
		}
	}
	return false
}

// RenderExecutionError writes one command execution error using the selected
// output format. JSON errors intentionally go to stdout for process consumers.
func RenderExecutionError(cmd *cobra.Command, err error, args []string) {
	if requestedJSON(cmd, args) || jsonEnabled(cmd) {
		_ = writeErrorJSON(cmd.OutOrStdout(), err)
		return
	}
	_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "Error: %v\n", err)
}
