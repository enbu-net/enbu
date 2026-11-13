package apperr

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/newmo-oss/ergo"
	"oras.land/oras-go/v2/registry/remote/errcode"
)

// Report is called at a transport boundary, once per failed operation. Raw error
// text and arbitrary attributes can contain secret values, so logs carry only
// classification, source stack, and safe structured diagnostic fields.
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
	attrs := []slog.Attr{
		slog.String("operation", operation), slog.String("code", string(payload.Code)),
		slog.String("stack", fmt.Sprintf("%+v", ergo.StackTraceOf(normalized))),
	}
	if cause := errors.Unwrap(normalized); cause != nil {
		for errors.Unwrap(cause) != nil {
			cause = errors.Unwrap(cause)
		}
		attrs = append(attrs, slog.String("cause_type", fmt.Sprintf("%T", cause)))
	}
	var staged stagedError
	if errors.As(normalized, &staged) {
		attrs = append(attrs, slog.String("stage", staged.stage))
	}
	var response *errcode.ErrorResponse
	if errors.As(normalized, &response) {
		attrs = append(attrs, slog.Int("http_status", response.StatusCode))
	}
	slog.Default().LogAttrs(ctx, level, "operation failed", attrs...)
}

type stagedError struct {
	stage string
	err   error
}

func (e stagedError) Error() string           { return e.err.Error() }
func (e stagedError) Unwrap() error           { return e.err }
func (e stagedError) DiagnosticStage() string { return e.stage }

// WithStage attaches a fixed operation stage for safe diagnostic logging.
// Stage names must not contain user input or secrets.
func WithStage(stage string, err error) error {
	if err == nil {
		return nil
	}
	return stagedError{stage: stage, err: err}
}
