package oci

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/enbu-net/enbu/apperr"
	"github.com/opencontainers/go-digest"
	"oras.land/oras-go/v2/errdef"
	"oras.land/oras-go/v2/registry/remote"
	"oras.land/oras-go/v2/registry/remote/auth"
	"oras.land/oras-go/v2/registry/remote/errcode"
)

func digestOf(data []byte) digest.Digest {
	h := sha256.Sum256(data)
	return digest.Digest(fmt.Sprintf("sha256:%x", h))
}

func bytesReader(data []byte) io.Reader {
	return bytes.NewReader(data)
}

func wrapRemoteError(message string, err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, errdef.ErrNotFound) {
		return apperr.Wrap(apperr.CodeArtifactNotFound, message, err, nil)
	}
	var response *errcode.ErrorResponse
	if errors.As(err, &response) && response.StatusCode == http.StatusNotFound {
		return apperr.Wrap(apperr.CodeArtifactNotFound, message, err, nil)
	}
	var registryError errcode.Error
	if errors.As(err, &registryError) &&
		(registryError.Code == errcode.ErrorCodeManifestUnknown ||
			registryError.Code == errcode.ErrorCodeNameUnknown) {
		return apperr.Wrap(apperr.CodeArtifactNotFound, message, err, nil)
	}
	return fmt.Errorf("%s: %w", message, err)
}

func newRepository(ref string, token string) (*remote.Repository, error) {
	repo, err := remote.NewRepository(ref)
	if err != nil {
		return nil, fmt.Errorf("parsing reference %q: %w", ref, err)
	}

	registry := repo.Reference.Registry
	if strings.HasPrefix(registry, "localhost:") || registry == "localhost" {
		repo.PlainHTTP = true
	}

	repo.Client = &auth.Client{
		Credential: auth.StaticCredential(registry, auth.Credential{
			Username: getUsername(),
			Password: token,
		}),
	}

	return repo, nil
}
