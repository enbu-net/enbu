package main

import (
	"bytes"
	"errors"
	"log/slog"
	"reflect"
	"strings"
	"testing"

	"github.com/enbu-net/enbu/pkg/apperr"
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
		apperr.CodeConflict,
		"workspace changed",
		apperr.Params{"commit": "sha256:abc"},
	))

	if response.Error == nil {
		t.Fatal("binding response has no error")
	}
	if response.Error.Code != apperr.CodeConflict {
		t.Fatalf("code = %q", response.Error.Code)
	}
	if response.Error.Params["commit"] != "sha256:abc" {
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

func TestDesktopBindingHasNoSecretPayloadOrOpenEndedActionMethods(t *testing.T) {
	typeOf := reflect.TypeOf((*DesktopService)(nil))
	for _, forbidden := range []string{
		"ListSecrets", "AddSecret", "EditSecret", "DeleteSecret", "PullSecrets", "ReadConfig", "WriteConfig", "StartHostOperation",
		"OpenWorkspace", "InitializeWorkspace",
	} {
		if _, exists := typeOf.MethodByName(forbidden); exists {
			t.Fatalf("forbidden Wails method %s is exported", forbidden)
		}
	}
}
