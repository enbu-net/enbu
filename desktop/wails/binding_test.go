package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"github.com/enbu-net/enbu/pkg/apperr"
)

func decodePayload(t *testing.T, data []byte) apperr.Payload {
	t.Helper()
	var payload apperr.Payload
	if err := json.Unmarshal(data, &payload); err != nil {
		t.Fatalf("decoding %q: %v", data, err)
	}
	return payload
}

func TestResultPassesValueAndNilError(t *testing.T) {
	value, err := result("dev", nil)
	if err != nil || value != "dev" {
		t.Fatalf("result() = %q, %v", value, err)
	}
	if publicError(nil) != nil {
		t.Fatal("publicError(nil) is not nil")
	}
}

func TestPublicErrorCarriesStructuredAppError(t *testing.T) {
	err := publicError(apperr.New(
		apperr.CodeEnvironmentMissing,
		"environment missing",
		apperr.Params{"name": "dev"},
	))
	payload := decodePayload(t, marshalError(err))
	if payload.Code != apperr.CodeEnvironmentMissing {
		t.Fatalf("code = %q", payload.Code)
	}
	if payload.Params["name"] != "dev" {
		t.Fatalf("params = %#v", payload.Params)
	}
}

func TestPublicErrorHidesInternalCause(t *testing.T) {
	err := publicError(errors.New("token=secret"))
	if strings.Contains(err.Error(), "secret") {
		t.Fatalf("error message leaks the cause: %q", err.Error())
	}
	data := marshalError(err)
	if bytes.Contains(data, []byte("secret")) {
		t.Fatalf("payload leaks the cause: %s", data)
	}
	if payload := decodePayload(t, data); payload.Code != apperr.CodeInternal {
		t.Fatalf("code = %q", payload.Code)
	}
}

func TestMarshalErrorNormalizesForeignErrors(t *testing.T) {
	// Errors from Wails itself, or wrapped by it, still reach the frontend
	// as an AppError payload.
	wrapped := fmt.Errorf("call failed: %w", publicError(apperr.New(apperr.CodeInvalidArgument, "bad", nil)))
	if payload := decodePayload(t, marshalError(wrapped)); payload.Code != apperr.CodeInvalidArgument {
		t.Fatalf("wrapped code = %q", payload.Code)
	}
	if payload := decodePayload(t, marshalError(errors.New("boom"))); payload.Code != apperr.CodeInternal {
		t.Fatalf("foreign code = %q", payload.Code)
	}
}

func TestPublicErrorLogsUnavailableCause(t *testing.T) {
	var logs bytes.Buffer
	previousLogger := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(previousLogger) })

	err := publicError(apperr.Wrap(
		apperr.CodeUnavailable,
		"keystore is unavailable",
		errors.New("opening keyring failed"),
		nil,
	))

	if payload := decodePayload(t, marshalError(err)); payload.Code != apperr.CodeUnavailable {
		t.Fatalf("code = %q", payload.Code)
	}
	if !strings.Contains(logs.String(), "opening keyring failed") {
		t.Fatalf("unavailable cause was not logged: %q", logs.String())
	}
}
