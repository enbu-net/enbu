package apperr

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/newmo-oss/ergo"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"oras.land/oras-go/v2/registry/remote/errcode"
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

func TestTypedNilError(t *testing.T) {
	var typedNil *Error
	wrapped := fmt.Errorf("wrapping: %w", typedNil)

	if Is(wrapped, CodeInternal) {
		t.Fatal("Is() should return false for typed-nil *Error")
	}
	if code := CodeOf(wrapped); code != CodeInternal {
		t.Fatalf("CodeOf() = %q, want %q", code, CodeInternal)
	}
	normalized := Normalize(wrapped)
	if normalized == nil {
		t.Fatal("Normalize() returned nil for non-nil error")
	}
}

func TestPayloadOfInternalHidesParams(t *testing.T) {
	err := Wrap(CodeInternal, "reading secret", errors.New("cause"), Params{"token": "secret-value"})
	payload := PayloadOf(err)
	if len(payload.Params) != 0 {
		t.Fatalf("internal error payload must not expose params, got %#v", payload.Params)
	}
}

func TestWorkspaceSecurityCodes(t *testing.T) {
	for _, code := range []Code{CodeNotMember, CodeUntrusted, CodeRollback, CodeIncompatibleStorage, CodeReencryptIncomplete} {
		if !IsKnownCode(code) {
			t.Fatalf("%q is not a known code", code)
		}
		params := Params{}
		for _, name := range definitions[code].params {
			params[name] = "test"
		}
		if got := PayloadOf(New(code, "message", params)).Code; got != code {
			t.Fatalf("payload code = %q, want %q", got, code)
		}
	}
	// Integrity failures and a device that is not approved each get their own
	// exit status so scripts can tell them from ordinary errors.
	if ExitCode(New(CodeNotMember, "pending", nil)) != 3 {
		t.Fatal("not_member exit code is not 3")
	}
	for _, code := range []Code{CodeUntrusted, CodeRollback} {
		if ExitCode(New(code, "integrity", nil)) != 5 {
			t.Fatalf("%s exit code is not 5", code)
		}
	}
}

func TestPublicPayloadDropsDetailsAndUndeclaredParams(t *testing.T) {
	err := Wrap(CodeSecretMissing, "token=secret", errors.New("private cause"), Params{"key": "NAME", "token": "secret"})
	p := PayloadOf(err)
	if p.Message != `Secret "NAME" does not exist.` || p.Params["key"] != "NAME" || len(p.Params) != 1 {
		t.Fatalf("unsafe payload: %#v", p)
	}
	if ergo.StackTraceOf(err) == nil {
		t.Fatal("missing stack")
	}
}
func TestReportDoesNotLogSecretDetails(t *testing.T) {
	var out bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&out, nil)))
	t.Cleanup(func() { slog.SetDefault(previous) })
	Report(context.Background(), "test", New(CodeInternal, "secret-value", Params{"token": "secret-value"}))
	if strings.Contains(out.String(), "secret-value") || !strings.Contains(out.String(), "error_test.go:") {
		t.Fatal(out.String())
	}
}

func TestReportIncludesSafeHTTPDiagnostics(t *testing.T) {
	var out bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&out, nil)))
	t.Cleanup(func() { slog.SetDefault(previous) })
	response := &errcode.ErrorResponse{
		Method:     "GET",
		URL:        &url.URL{Scheme: "https", Host: "ghcr.io", Path: "/secret-path", RawQuery: "token=secret-value"},
		StatusCode: http.StatusForbidden,
		Errors:     errcode.Errors{{Code: "DENIED", Message: "secret-value"}},
	}
	Report(context.Background(), "desktop", fmt.Errorf("secret-value: %w", response))
	var record map[string]any
	if err := json.Unmarshal(out.Bytes(), &record); err != nil {
		t.Fatal(err)
	}
	if record["http_status"] != float64(http.StatusForbidden) || record["cause_type"] == "" {
		t.Fatalf("missing safe HTTP diagnostics: %s", out.String())
	}
	if strings.Contains(out.String(), "secret-value") || strings.Contains(out.String(), "/secret-path") {
		t.Fatalf("logged sensitive error details: %s", out.String())
	}
}

func TestReportIncludesDiagnosticStage(t *testing.T) {
	var out bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&out, nil)))
	t.Cleanup(func() { slog.SetDefault(previous) })
	Report(context.Background(), "desktop", WithStage("init.ensure_control", errors.New("secret-value")))
	if !strings.Contains(out.String(), `"stage":"init.ensure_control"`) || strings.Contains(out.String(), "secret-value") {
		t.Fatal(out.String())
	}
}

func TestNormalizePreservesWrappedText(t *testing.T) {
	original := fmt.Errorf("syncing: %w", New(CodeConflict, "changed", nil))
	if got := Normalize(original); got.Error() != original.Error() {
		t.Fatalf("got %q want %q", got, original)
	}
}
func TestMissingPublicParameterIsInternal(t *testing.T) {
	for _, params := range []Params{nil, {"key": ""}} {
		if p := PayloadOf(New(CodeSecretMissing, "detail", params)); p.Code != CodeInternal || len(p.Params) != 0 {
			t.Fatal(p)
		}
	}
}
func TestIdentityPayloadDoesNotExposeBackendReason(t *testing.T) {
	p := PayloadOf(New(CodeIdentityUnavailable, "private cause", Params{"reason": "secret-value"}))
	if strings.Contains(p.Message, "secret-value") || len(p.Params) != 0 {
		t.Fatal(p)
	}
}
