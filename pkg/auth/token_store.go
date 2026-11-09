package auth

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"

	"github.com/enbu-net/enbu/pkg/apperr"
	"github.com/enbu-net/enbu/pkg/keystore"
	"github.com/enbu-net/enbu/pkg/winbridge"
)

const (
	tokenKeyringService = "enbu"
	tokenKeyringAccount = "github-oauth"
)

// tokenBackend holds the token in the OS keyring. A missing or locked keyring
// is an error; there is no plaintext file to fall back to. Inside WSL it is
// the Windows keyring, through enbu.exe, so Windows and every distribution
// share one sign-in.
var tokenBackend = newTokenBackend()

func newTokenBackend() keystore.Backend {
	if winbridge.InWSL() {
		return winbridge.Shared().Keyring()
	}
	return keystore.New()
}

// TokenKeyringEntry is the OS keyring entry of the GitHub token, which the
// Windows enbu.exe shares with WSL.
func TokenKeyringEntry() (service, key string) { return tokenKeyringService, tokenKeyringAccount }

// keyringError tells the person what to fix instead of showing an internal
// error: a locked OS keyring gets its own code, a missing one is unavailable.
func keyringError(op string, err error) error {
	switch {
	case errors.Is(err, keystore.ErrLocked):
		return apperr.Wrap(apperr.CodeKeyringLocked, op+": "+err.Error(), err, nil)
	case errors.Is(err, keystore.ErrNoKeyring):
		return apperr.Wrap(apperr.CodeUnavailable, op+": "+err.Error(), err, nil)
	}
	return fmt.Errorf("%s: %w", op, err)
}

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
		return keyringError("saving token", err)
	}
	stored, err := tokenBackend.Load(tokenKeyringService, tokenKeyringAccount)
	if err != nil {
		return keyringError("verifying saved token", err)
	}
	if !bytes.Equal(stored, data) {
		return errors.New("verifying saved token failed")
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
		return nil, keyringError("loading token", err)
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
	if err := tokenBackend.Delete(tokenKeyringService, tokenKeyringAccount); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return keyringError("removing token", err)
	}
	return nil
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
