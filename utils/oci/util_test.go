package oci

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"testing"

	"github.com/enbu-net/enbu/apperr"
	"oras.land/oras-go/v2/errdef"
	"oras.land/oras-go/v2/registry/remote/errcode"
)

func TestDigestOf(t *testing.T) {
	data := []byte("hello world")
	digest := digestOf(data)

	expected := "sha256:b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
	if string(digest) != expected {
		t.Errorf("digest = %q, want %q", digest, expected)
	}
}

func TestDigestOfEmpty(t *testing.T) {
	data := []byte("")
	digest := digestOf(data)

	expected := "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	if string(digest) != expected {
		t.Errorf("digest = %q, want %q", digest, expected)
	}
}

func TestBytesReader(t *testing.T) {
	data := []byte("test content")
	r := bytesReader(data)

	got, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if string(got) != string(data) {
		t.Errorf("got %q, want %q", got, data)
	}
}

func TestWrapRemoteErrorClassifiesORASNotFound(t *testing.T) {
	tests := []struct {
		name  string
		cause error
	}{
		{name: "ORAS sentinel", cause: fmt.Errorf("resolving reference: %w", errdef.ErrNotFound)},
		{name: "HTTP 404", cause: &errcode.ErrorResponse{StatusCode: http.StatusNotFound}},
		{name: "manifest unknown", cause: errcode.Error{Code: errcode.ErrorCodeManifestUnknown}},
		{name: "name unknown", cause: errcode.Error{Code: errcode.ErrorCodeNameUnknown}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := wrapRemoteError("pulling secrets", tt.cause)
			if !apperr.Is(err, apperr.CodeArtifactNotFound) {
				t.Fatalf("code = %q, want %q", apperr.CodeOf(err), apperr.CodeArtifactNotFound)
			}
			if !errors.Is(err, tt.cause) {
				t.Fatal("wrapped error does not preserve the ORAS cause")
			}
		})
	}
}
