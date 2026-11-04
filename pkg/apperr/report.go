package apperr

import (
	"context"
	"fmt"
	"github.com/newmo-oss/ergo"
	"log/slog"
)

// Report is called at a transport boundary, once per failed operation. Raw error
// text and arbitrary attributes can contain secret values, so normal logs carry
// only the classification, operation, and source stack.
func Report(ctx context.Context, operation string, err error) {
	if err == nil {
		return
	}
	normalized := Normalize(err)
	payload := PayloadOf(normalized)
	level := slog.LevelWarn
	if payload.Code == CodeInternal || payload.Code == CodeUnavailable {
		level = slog.LevelError
	}
	slog.Default().LogAttrs(ctx, level, "operation failed",
		slog.String("operation", operation), slog.String("code", string(payload.Code)),
		slog.String("stack", fmt.Sprintf("%+v", ergo.StackTraceOf(normalized))))
}
