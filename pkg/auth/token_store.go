package auth

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/enbu-net/enbu/pkg/apperr"
	"github.com/enbu-net/enbu/pkg/config"
	"github.com/enbu-net/enbu/pkg/keystore"
)

const (
	tokenKeyringService = "enbu"
	tokenKeyringAccount = "github-oauth"
)

var tokenBackend = func() keystore.Backend {
	b, err := keystore.New()
	if err != nil || b == nil {
		return &keystore.TextBackend{}
	}
	return b
}()

type StoredToken struct {
	AccessToken string `json:"access_token"`
	Username    string `json:"username"`
	UserID      int64  `json:"user_id"`
}

func SaveToken(token *StoredToken) error {
	if err := validateStoredToken(token); err != nil {
		return err
	}
	data, err := json.Marshal(token)
	if err != nil {
		return err
	}
	if err := tokenBackend.Store(tokenKeyringService, tokenKeyringAccount, data); err != nil {
		return fmt.Errorf("saving token: %w", err)
	}
	stored, err := tokenBackend.Load(tokenKeyringService, tokenKeyringAccount)
	if err != nil || !bytes.Equal(stored, data) {
		return errors.New("verifying saved token failed")
	}
	if err := os.Remove(legacyTokenPath()); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("removing legacy token file: %w", err)
	}
	return nil
}

func LoadToken() (*StoredToken, error) {
	if tokenEnv := os.Getenv("GITHUB_TOKEN"); tokenEnv != "" {
		actor := os.Getenv("GITHUB_ACTOR")
		if actor == "" {
			actor = "github-actions"
		}
		return &StoredToken{AccessToken: tokenEnv, Username: actor}, nil
	}

	data, err := tokenBackend.Load(tokenKeyringService, tokenKeyringAccount)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, notLoggedInError()
		}
		return nil, fmt.Errorf("loading token: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var token StoredToken
	if err := decoder.Decode(&token); err != nil {
		return nil, fmt.Errorf("parsing token: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return nil, errors.New("parsing token: invalid trailing data")
	}
	if err := validateStoredToken(&token); err != nil {
		return nil, fmt.Errorf("parsing token: %w", err)
	}
	return &token, nil
}

func DeleteToken() error {
	var deleteErrors []error
	if err := tokenBackend.Delete(tokenKeyringService, tokenKeyringAccount); err != nil && !errors.Is(err, fs.ErrNotExist) {
		deleteErrors = append(deleteErrors, fmt.Errorf("removing token: %w", err))
	}
	if err := os.Remove(legacyTokenPath()); err != nil && !os.IsNotExist(err) {
		deleteErrors = append(deleteErrors, fmt.Errorf("removing legacy token file: %w", err))
	}
	return errors.Join(deleteErrors...)
}

func validateStoredToken(token *StoredToken) error {
	if token == nil || token.AccessToken == "" || len(token.AccessToken) > 2048 {
		return errors.New("invalid access token")
	}
	if token.Username == "" || len(token.Username) > 256 || token.UserID <= 0 {
		return errors.New("invalid GitHub identity")
	}
	return nil
}

func notLoggedInError() error {
	return apperr.New(apperr.CodeNotAuthenticated, "not logged in: run 'enbu auth login' to authenticate with GitHub", nil)
}

func legacyTokenPath() string {
	return filepath.Join(config.DataDir(), "token.json")
}
