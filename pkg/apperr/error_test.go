package apperr

import (
	"errors"
	"fmt"
	"testing"
)

func TestErrorWrapPreservesCauseAndCode(t *testing.T) {
	cause := errors.New("disk full")
	err := Wrap(CodeUnavailable, "saving config", cause, Params{"path": "enbu.toml"})

	if got := err.Error(); got != "saving config: disk full" {
		t.Fatalf("Error() = %q", got)
	}
	if !errors.Is(err, cause) {
		t.Fatal("wrapped cause is not reachable with errors.Is")
	}
	if !Is(err, CodeUnavailable) {
		t.Fatal("code is not reachable through the error chain")
	}
}

func TestParamsAreDefensivelyCopied(t *testing.T) {
	input := Params{"name": "default"}
	err := New(CodeEnvironmentMissing, "environment missing", input)
	input["name"] = "changed"

	got := err.Params()
	got["name"] = "changed again"
	if value := err.Params()["name"]; value != "default" {
		t.Fatalf("stored param = %q", value)
	}
}

func TestNormalize(t *testing.T) {
	cause := errors.New("boom")
	normalized := Normalize(cause)
	if !Is(normalized, CodeInternal) || !errors.Is(normalized, cause) {
		t.Fatalf("Normalize() = %v", normalized)
	}

	known := New(CodeConflict, "changed", nil)
	if got := Normalize(known); got != known {
		t.Fatal("Normalize changed a direct AppError")
	}

	wrapped := fmt.Errorf("syncing: %w", known)
	normalized = Normalize(wrapped)
	var appErr *Error
	if !errors.As(normalized, &appErr) || appErr.Code() != CodeConflict {
		t.Fatalf("Normalize(wrapped) = %#v", normalized)
	}
}

func TestPayloadAndExitCode(t *testing.T) {
	err := Wrap(CodeInternal, "reading secret", errors.New("token=secret"), nil)
	payload := PayloadOf(err)
	if payload.Message != "An unexpected error occurred." {
		t.Fatalf("internal message = %q", payload.Message)
	}
	if ExitCode(New(CodeInvalidArgument, "bad input", nil)) != 2 {
		t.Fatal("invalid argument exit code is not 2")
	}
	if ExitCode(New(CodeAccessDenied, "denied", nil)) != 3 {
		t.Fatal("access denied exit code is not 3")
	}
	if ExitCode(New(CodeConflict, "changed", nil)) != 4 {
		t.Fatal("conflict exit code is not 4")
	}
}

func TestPayloadRejectsUnknownCode(t *testing.T) {
	payload := PayloadOf(New(Code("future_code"), "token=secret", Params{"token": "secret"}))
	if payload.Code != CodeInternal {
		t.Fatalf("code = %q, want %q", payload.Code, CodeInternal)
	}
	if payload.Message != "An unexpected error occurred." {
		t.Fatalf("message = %q", payload.Message)
	}
	if len(payload.Params) != 0 {
		t.Fatalf("params = %#v", payload.Params)
	}
}
