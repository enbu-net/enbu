package main

import (
	"context"
	"errors"
	"testing"

	"github.com/spf13/cobra"
)

func TestExecuteCommandPreservesError(t *testing.T) {
	want := errors.New("command failure")
	command := &cobra.Command{
		Use: "enbu", SilenceErrors: true, SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if cmd.Context() == nil {
				t.Error("missing command context")
			}
			return want
		},
	}
	command.SetArgs(nil)
	if err := executeCommand(context.Background(), command); !errors.Is(err, want) {
		t.Fatalf("error = %v, want %v", err, want)
	}
}
