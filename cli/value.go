package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/term"
)

// secretValue returns the value for add and edit. It comes from the VALUE
// argument, from --value-file (or "-" for stdin), or, without either, from
// stdin: a hidden prompt on a terminal, the whole input otherwise. Values that
// stay off the command line do not end up in shell history or `ps`.
func secretValue(cmd *cobra.Command, args []string, valueFile string) (string, error) {
	if len(args) == 2 && valueFile != "" {
		return "", invalidArgument("give the value either as an argument or with --value-file, not both", nil)
	}
	if len(args) == 2 {
		return args[1], nil
	}
	var data []byte
	var err error
	switch {
	case valueFile != "" && valueFile != "-":
		data, err = os.ReadFile(valueFile)
	case valueFile == "" && interactive(cmd):
		_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "Value for %s (hidden): ", args[0])
		data, err = readHiddenLine()
		_, _ = fmt.Fprintln(cmd.ErrOrStderr())
	default:
		data, err = io.ReadAll(cmd.InOrStdin())
	}
	if err != nil {
		return "", invalidArgument("reading the value", err)
	}
	value := strings.TrimSuffix(strings.TrimSuffix(string(data), "\n"), "\r")
	if value == "" {
		return "", invalidArgument("the value is empty: pass VALUE, --value-file, or write it to stdin", nil)
	}
	return value, nil
}

// readHiddenLine is a variable so tests can run without a terminal.
var readHiddenLine = func() ([]byte, error) {
	b, err := term.ReadPassword(int(os.Stdin.Fd()))
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	return b, nil
}
