package main

import (
	"bytes"
	"errors"
	"log/slog"
	"reflect"
	"strings"
	"testing"

	"github.com/enbu-net/enbu/apperr"
)

func TestBindingResultReturnsData(t *testing.T) {
	data := map[string]string{"environment": "dev"}
	response := bindingResult(data, nil)

	if response.Error != nil {
		t.Fatalf("binding response error = %#v", response.Error)
	}
	if !reflect.DeepEqual(response.Data, data) {
		t.Fatalf("binding response data = %#v, want %#v", response.Data, data)
	}
}

func TestBindingResultReturnsStructuredAppError(t *testing.T) {
	response := bindingResult[any](nil, apperr.New(
		apperr.CodeEnvironmentMissing,
		"environment missing",
		apperr.Params{"name": "dev"},
	))

	if response.Error == nil {
		t.Fatal("binding response has no error")
	}
	if response.Error.Code != apperr.CodeEnvironmentMissing {
		t.Fatalf("code = %q", response.Error.Code)
	}
	if response.Error.Params["name"] != "dev" {
		t.Fatalf("params = %#v", response.Error.Params)
	}
}

func TestBindingResultHidesInternalCause(t *testing.T) {
	response := bindingResult[any](nil, errors.New("token=secret"))
	if response.Error == nil {
		t.Fatal("binding response has no error")
	}
	if response.Error.Code != apperr.CodeInternal {
		t.Fatalf("code = %q", response.Error.Code)
	}
	if response.Error.Message != "An unexpected error occurred." {
		t.Fatalf("message = %q", response.Error.Message)
	}
}

func TestBindingResultLogsUnavailableCause(t *testing.T) {
	var logs bytes.Buffer
	previousLogger := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(previousLogger) })

	response := bindingResult[any](nil, apperr.Wrap(
		apperr.CodeUnavailable,
		"keystore is unavailable",
		errors.New("opening keyring failed"),
		nil,
	))

	if response.Error == nil || response.Error.Code != apperr.CodeUnavailable {
		t.Fatalf("binding response error = %#v", response.Error)
	}
	if !strings.Contains(logs.String(), "opening keyring failed") {
		t.Fatalf("unavailable cause was not logged: %q", logs.String())
	}
}
