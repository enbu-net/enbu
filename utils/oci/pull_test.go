package oci

import (
	"errors"
	"fmt"
	"net/http"
	"testing"

	"oras.land/oras-go/v2/errdef"
	"oras.land/oras-go/v2/registry/remote/errcode"
)

func TestIsNotFound(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{name: "nil", err: nil, want: false},
		{name: "sentinel", err: ErrNotFound, want: true},
		{name: "ORAS sentinel", err: fmt.Errorf("resolve failed: %w", errdef.ErrNotFound), want: true},
		{
			name: "wrapped manifest unknown",
			err:  fmt.Errorf("pull failed: %w", errcode.Error{Code: errcode.ErrorCodeManifestUnknown}),
			want: true,
		},
		{
			name: "name unknown",
			err:  errcode.Error{Code: errcode.ErrorCodeNameUnknown},
			want: true,
		},
		{
			name: "plain HTTP not found",
			err:  &errcode.ErrorResponse{StatusCode: http.StatusNotFound},
			want: true,
		},
		{
			name: "denied",
			err:  errcode.Error{Code: errcode.ErrorCodeDenied},
			want: false,
		},
		{
			name: "forbidden",
			err:  &errcode.ErrorResponse{StatusCode: http.StatusForbidden},
			want: false,
		},
		{name: "plain text", err: errors.New("not found"), want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsNotFound(tt.err); got != tt.want {
				t.Fatalf("IsNotFound() = %v, want %v", got, tt.want)
			}
		})
	}
}
