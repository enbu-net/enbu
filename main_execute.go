//go:build !enbucoverage

package main

import (
	"context"

	"github.com/spf13/cobra"
)

func executeCommand(ctx context.Context, command *cobra.Command) error {
	return runCommand(ctx, command)
}
