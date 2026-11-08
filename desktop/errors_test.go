package desktop

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"reflect"
	"strings"
	"testing"

	"github.com/enbu-net/enbu/app"
	"github.com/enbu-net/enbu/app/apptest"
	"github.com/enbu-net/enbu/pkg/apperr"
	"github.com/enbu-net/enbu/pkg/auth"
	"github.com/enbu-net/enbu/pkg/clock"
)

func TestPublicErrorKeepsStructuredAppError(t *testing.T) {
	err := publicError(fmt.Errorf("wrapped: %w", apperr.New(apperr.CodeEnvironmentMissing, "environment missing", apperr.Params{"name": "dev"})))
	if !apperr.Is(err, apperr.CodeEnvironmentMissing) {
		t.Fatalf("code lost: %v", err)
	}
	if payload := ErrorPayload(err); payload.Code != apperr.CodeEnvironmentMissing || payload.Params["name"] != "dev" {
		t.Fatalf("payload = %+v", payload)
	}
	if publicError(nil) != nil {
		t.Fatal("publicError(nil) is not nil")
	}
}

func TestPublicErrorHidesInternalCause(t *testing.T) {
	err := publicError(errors.New("token=secret"))
	if strings.Contains(err.Error(), "secret") {
		t.Fatalf("error message leaks the cause: %q", err.Error())
	}
	if payload := ErrorPayload(err); payload.Code != apperr.CodeInternal || strings.Contains(payload.Message, "secret") {
		t.Fatalf("payload = %+v", payload)
	}
	// A transport wrapping the error still finds the payload.
	if payload := ErrorPayload(fmt.Errorf("call failed: %w", err)); payload.Code != apperr.CodeInternal {
		t.Fatalf("wrapped payload = %+v", payload)
	}
	if payload := ErrorPayload(errors.New("from the transport")); payload.Code != apperr.CodeInternal {
		t.Fatalf("foreign payload = %+v", payload)
	}
}

func TestPublicErrorLogsClassificationWithoutCause(t *testing.T) {
	var logs bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(previous) })

	err := publicError(apperr.Wrap(apperr.CodeUnavailable, "keystore is unavailable", errors.New("opening keyring failed"), nil))
	if payload := ErrorPayload(err); payload.Code != apperr.CodeUnavailable {
		t.Fatalf("code = %q", payload.Code)
	}
	if strings.Contains(logs.String(), "opening keyring failed") || !strings.Contains(logs.String(), "code=unavailable") {
		t.Fatalf("unsafe or missing classification log: %q", logs.String())
	}
	// Mapping it again, as a transport does, does not log it twice.
	logs.Reset()
	_ = ErrorPayload(err)
	if logs.Len() != 0 {
		t.Fatalf("logged again: %q", logs.String())
	}
}

// Every method the frontend can call fails with an *Error, so no transport
// ever sees an internal cause. Called with zero arguments and no workspace,
// most of them fail.
func TestEveryServiceMethodFailsWithPublicError(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("GITHUB_TOKEN", "")
	a := app.New(clock.New())
	a.Identities = &apptest.Identities{}
	s := NewService(a)
	s.authLogin = func(context.Context, auth.DevicePrompter) (*auth.StoredToken, error) {
		return nil, errors.New("login cause")
	}
	failures := 0
	value := reflect.ValueOf(s)
	for i := range value.NumMethod() {
		method := value.Type().Method(i)
		if method.Name == "Logout" {
			continue // it would delete this machine's GitHub token
		}
		args := make([]reflect.Value, method.Type.NumIn()-1)
		for j := range args {
			args[j] = reflect.Zero(method.Type.In(j + 1))
		}
		for _, out := range value.Method(i).Call(args) {
			err, ok := out.Interface().(error)
			if !ok || err == nil {
				continue
			}
			failures++
			if _, public := err.(*Error); !public {
				t.Errorf("%s returned %T, not *Error", method.Name, err)
			}
		}
	}
	if failures < 20 {
		t.Fatalf("only %d methods failed; the check covers too little", failures)
	}
}
