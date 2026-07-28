package main

import (
	"errors"
	"testing"

	"github.com/enbu-net/enbu/apperr"
)

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
