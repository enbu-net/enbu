package auth

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/enbu-net/enbu/pkg/apperr"
	"github.com/enbu-net/enbu/pkg/config"
	"github.com/enbu-net/enbu/pkg/fsutil"
	"github.com/enbu-net/enbu/pkg/keystore"
	"github.com/enbu-net/enbu/pkg/winbridge"
)

const (
	tokenKeyringService = "enbu"
	tokenKeyringAccount = "github-oauth"
)

// tokenBackend holds the tokens in the OS keyring. A missing or locked keyring
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

// storedAccounts is the keyring entry: every GitHub account this OS user
// signed in with, the most recent sign-in last. Which one is in use is not
// kept here but in the data directory (activeAccount), so two data
// directories, such as two people trying a workspace on one computer, can use
// two accounts from one keyring.
type storedAccounts struct {
	Accounts []StoredToken `json:"accounts"`
}

// activeAccount names the account in use by its GitHub user ID, which stays
// the same when the account is renamed.
type activeAccount struct {
	UserID int64 `json:"user_id"`
}

// activePath is where this data directory records the account in use.
var activePath = func() string { return filepath.Join(config.DataDir(), "github-account.json") }

// SaveToken adds the account, or replaces its token when it is already signed
// in, and makes it the account in use. The choice is written first, and put
// back if the keyring then fails, so a failed sign-in changes nothing.
//
// Two sign-ins at the same moment, such as the CLI and the desktop app, may
// keep only one of the two accounts; signing in again adds the other.
func SaveToken(token *StoredToken) error {
	if err := validateStoredToken(token); err != nil {
		return err
	}
	accounts, err := loadAccounts()
	if err != nil {
		return err
	}
	kept := accounts[:0]
	for _, a := range accounts {
		if a.UserID != token.UserID {
			kept = append(kept, a)
		}
	}
	previous := loadActive()
	if err := setActive(token.UserID); err != nil {
		return err
	}
	if err := storeAccounts(append(kept, *token)); err != nil {
		if restoreErr := setActive(previous); restoreErr != nil {
			slog.Warn("could not restore the GitHub account in use", "err", restoreErr)
		}
		return err
	}
	return nil
}

// LoadToken returns GITHUB_TOKEN when it is set, otherwise the account in use.
func LoadToken() (*StoredToken, error) {
	if tokenEnv := os.Getenv("GITHUB_TOKEN"); tokenEnv != "" {
		actor := os.Getenv("GITHUB_ACTOR")
		if actor == "" {
			actor = "github-actions"
		}
		return &StoredToken{AccessToken: tokenEnv, Username: actor}, nil
	}
	accounts, err := loadAccounts()
	if err != nil {
		return nil, err
	}
	current := currentIndex(accounts)
	if current < 0 {
		return nil, notLoggedInError()
	}
	token := accounts[current]
	return &token, nil
}

// Accounts lists the signed-in GitHub logins, the most recent sign-in last,
// and the one in use, "" when there is none. GITHUB_TOKEN is not an account.
func Accounts() (logins []string, current string, err error) {
	accounts, err := loadAccounts()
	if err != nil {
		return nil, "", err
	}
	for _, a := range accounts {
		logins = append(logins, a.Username)
	}
	if i := currentIndex(accounts); i >= 0 {
		current = accounts[i].Username
	}
	return logins, current, nil
}

// SwitchAccount makes the signed-in account login the one in use in this data
// directory. The login is matched without regard to case, as GitHub does.
func SwitchAccount(login string) (*StoredToken, error) {
	accounts, err := loadAccounts()
	if err != nil {
		return nil, err
	}
	i := indexOf(accounts, login)
	if i < 0 {
		return nil, apperr.New(apperr.CodeInvalidArgument, fmt.Sprintf("not signed in as %q: run 'enbu auth login' to add the account", login), nil)
	}
	if err := setActive(accounts[i].UserID); err != nil {
		return nil, err
	}
	token := accounts[i]
	return &token, nil
}

// UseLatestAccount makes the most recent sign-in the account in use. Inside
// WSL the Windows enbu.exe signs in, so this data directory follows it here.
func UseLatestAccount() error {
	accounts, err := loadAccounts()
	if err != nil {
		return err
	}
	if len(accounts) == 0 {
		return notLoggedInError()
	}
	return setActive(accounts[len(accounts)-1].UserID)
}

// DeleteToken signs out of the account in use. The most recent remaining
// sign-in is used next.
func DeleteToken() error {
	return DeleteAccount("")
}

// DeleteAccount signs out of the account login, or of the one in use when
// login is "". Signing out of no account is not an error.
func DeleteAccount(login string) error {
	accounts, err := loadAccounts()
	if err != nil {
		return err
	}
	i := currentIndex(accounts)
	if login != "" {
		if i = indexOf(accounts, login); i < 0 {
			return apperr.New(apperr.CodeInvalidArgument, fmt.Sprintf("not signed in as %q", login), nil)
		}
	}
	if i < 0 {
		return nil
	}
	return storeAccounts(append(accounts[:i:i], accounts[i+1:]...))
}

func indexOf(accounts []StoredToken, login string) int {
	for i, a := range accounts {
		if strings.EqualFold(a.Username, login) {
			return i
		}
	}
	return -1
}

// currentIndex is the account this data directory chose, or the most recent
// sign-in when it chose none or signed out of the one it chose.
func currentIndex(accounts []StoredToken) int {
	if id := loadActive(); id != 0 {
		for i, a := range accounts {
			if a.UserID == id {
				return i
			}
		}
	}
	return len(accounts) - 1
}

func loadAccounts() ([]StoredToken, error) {
	data, err := tokenBackend.Load(tokenKeyringService, tokenKeyringAccount)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, keyringError("loading token", err)
	}
	accounts, err := parseAccounts(data)
	if err != nil {
		// An entry an earlier version saved, or a damaged one, holds no
		// account this version can use: the person signs in again, which
		// replaces it.
		slog.Warn("ignoring the stored GitHub sign-in; run 'enbu auth login'", "err", err)
		return nil, nil
	}
	return accounts, nil
}

func parseAccounts(data []byte) ([]StoredToken, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var stored storedAccounts
	if err := decoder.Decode(&stored); err != nil {
		return nil, fmt.Errorf("parsing token: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return nil, errors.New("parsing token: invalid trailing data")
	}
	for i := range stored.Accounts {
		if err := validateStoredToken(&stored.Accounts[i]); err != nil {
			return nil, fmt.Errorf("parsing token: %w", err)
		}
	}
	return stored.Accounts, nil
}

func storeAccounts(accounts []StoredToken) error {
	if len(accounts) == 0 {
		if err := tokenBackend.Delete(tokenKeyringService, tokenKeyringAccount); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return keyringError("removing token", err)
		}
		return nil
	}
	data, err := json.Marshal(storedAccounts{Accounts: accounts})
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

// loadActive is the user ID this data directory chose, or 0. A missing or
// damaged file only means no choice: the most recent sign-in is used.
func loadActive() int64 {
	data, err := os.ReadFile(activePath())
	if err != nil {
		return 0
	}
	var active activeAccount
	if json.Unmarshal(data, &active) != nil {
		return 0
	}
	return active.UserID
}

func setActive(userID int64) error {
	path := activePath()
	if err := fsutil.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("choosing the GitHub account: %w", err)
	}
	data, err := json.Marshal(activeAccount{UserID: userID})
	if err != nil {
		return err
	}
	if err := fsutil.WriteFileAtomic(path, data, 0o600); err != nil {
		return fmt.Errorf("choosing the GitHub account: %w", err)
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
