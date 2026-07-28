package main

import (
	"errors"
	"reflect"
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
