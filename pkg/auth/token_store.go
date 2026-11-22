package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/enbu-net/enbu/pkg/apperr"
	"github.com/enbu-net/enbu/pkg/config"
	"github.com/enbu-net/enbu/pkg/fsutil"
	"github.com/enbu-net/enbu/pkg/winbridge"
)

type StoredToken struct {
	AccessToken string `json:"access_token"`
	Username    string `json:"username"`
	UserID      int64  `json:"user_id"`
}

// storedAccounts contains every GitHub account this OS user
// signed in with, the most recent sign-in last. Which one is in use is not
// kept here but in the data directory (activeAccount), so two data
// directories, such as two people trying a workspace on one computer, can use
// two accounts from one credential store.
type storedAccounts struct {
	Accounts     []StoredToken `json:"accounts"`
	Migration    string        `json:"migration,omitempty"`
	LegacyDigest string        `json:"legacy_digest,omitempty"`
}

// activeAccount names the account in use by its GitHub user ID, which stays
// the same when the account is renamed.
type activeAccount struct {
	UserID int64 `json:"user_id"`
}

// activePath is where this data directory records the account in use.
var activePath = func() string { return filepath.Join(config.DataDir(), "github-account.json") }

// SaveToken adds or replaces an account and makes it the account in use.
func SaveToken(token *StoredToken) error {
	if err := validateStoredToken(token); err != nil {
		return err
	}
	if TokenFromEnvironment() != nil {
		return nil
	}
	if winbridge.InWSL() {
		return saveWithSelection(token.UserID, func() error {
			_, err := accountOperation("save", accountRequest{Token: token})
			return err
		})
	}
	s := localStores()
	return s.withLock(func() error {
		_, err := s.execute("save", accountRequest{Token: token, selectLocally: true})
		return err
	})
}

func saveWithSelection(userID int64, save func() error) error {
	previous := loadActive()
	if err := setActive(userID); err != nil {
		return err
	}
	if err := save(); err != nil {
		if restoreErr := setActive(previous); restoreErr != nil {
			slog.Warn("could not restore the GitHub account in use", "err", restoreErr)
		}
		return err
	}
	return nil
}

// TokenFromEnvironment returns the ephemeral GitHub credential, if supplied.
func TokenFromEnvironment() *StoredToken {
	token := os.Getenv("GITHUB_TOKEN")
	if token == "" {
		return nil
	}
	actor := os.Getenv("GITHUB_ACTOR")
	if actor == "" {
		actor = "github-actions"
	}
	return &StoredToken{AccessToken: token, Username: actor}
}

// LoadToken returns GITHUB_TOKEN when it is set, otherwise the account in use.
func LoadToken() (*StoredToken, error) {
	if token := TokenFromEnvironment(); token != nil {
		return token, nil
	}
	result, err := readAccountOperation("load", "")
	return result.Token, err
}

// Accounts lists saved accounts, the most recent sign-in last, and the one in use.
func Accounts() (logins []string, current string, err error) {
	result, err := readAccountOperation("list", "")
	return result.Logins, result.Current, err
}

// SwitchAccount makes a signed-in account the active account in this data directory.
func SwitchAccount(login string) (*StoredToken, error) {
	request := accountRequest{Login: login}
	if winbridge.InWSL() {
		result, err := accountOperation("switch", request)
		return selectAccount(result, err)
	}
	s := localStores()
	var token *StoredToken
	err := s.withLock(func() error {
		result, err := s.execute("switch", request)
		token, err = selectAccount(result, err)
		return err
	})
	return token, err
}

func selectAccount(result accountResult, err error) (*StoredToken, error) {
	if err != nil {
		return nil, err
	}
	if result.Token == nil {
		return nil, notLoggedInError()
	}
	if err := setActive(result.Token.UserID); err != nil {
		return nil, err
	}
	return result.Token, nil
}

// DeleteToken signs out of the account in use.
func DeleteToken() error { return DeleteAccount("") }

// DeleteAccount signs out of the matching account. Local stores also allow the
// account in use, since their result is not subject to bridge timeouts.
func DeleteAccount(login string) error {
	if winbridge.InWSL() {
		if strings.TrimSpace(login) == "" {
			return apperr.New(apperr.CodeInvalidArgument, "on WSL, use enbu auth logout --user LOGIN", nil)
		}
		_, err := accountOperation("delete", accountRequest{Login: login, Active: loadActive()})
		return err
	}
	s := localStores()
	return s.withLock(func() error {
		_, err := s.execute("delete", accountRequest{Login: login, Active: loadActive()})
		return err
	})
}

func readAccountOperation(operation, login string) (accountResult, error) {
	return accountOperation(operation, accountRequest{Login: login, Active: loadActive()})
}

func accountOperation(operation string, request accountRequest) (accountResult, error) {
	var result accountResult
	if winbridge.InWSL() {
		err := winbridge.Shared().GitHubAuth(operation, request, &result)
		return result, bridgeAuthError(err)
	}
	return localStores().execute(operation, request)
}

type accountRequest struct {
	Token  *StoredToken `json:"token,omitempty"`
	Active int64        `json:"active,omitempty"`
	Login  string       `json:"login,omitempty"`

	selectLocally bool
}

type accountResult struct {
	Token   *StoredToken `json:"token,omitempty"`
	Logins  []string     `json:"logins,omitempty"`
	Current string       `json:"current,omitempty"`
}

func (s credentialStores) withLock(fn func() error) error {
	f, err := s.lock()
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	return fn()
}

// ServeGitHubAuth serves only GitHub credential operations on the Windows
// side of the bridge. Active-account IDs come from the caller's WSL data dir.
func ServeGitHubAuth(_ context.Context, operation string, raw json.RawMessage) (any, error) {
	s := localStores()
	switch operation {
	case "diagnose":
		return s.diagnose(), nil
	case "open_device_browser":
		return struct{}{}, openBrowser(deviceVerificationURL)
	case "migrate", "reset":
		return struct{}{}, s.maintain(operation)
	case "save", "delete", "load", "list", "switch":
		var request accountRequest
		if err := decodeStrict(raw, &request); err != nil {
			return nil, err
		}
		if operation == "save" || operation == "delete" {
			var result accountResult
			err := s.withLock(func() error {
				var err error
				result, err = s.execute(operation, request)
				return err
			})
			return result, err
		}
		return s.execute(operation, request)
	default:
		return nil, errors.New("unknown GitHub credential operation")
	}
}

func (s credentialStores) execute(operation string, request accountRequest) (accountResult, error) {
	var result accountResult
	store, _, err := s.choose(false)
	if err != nil {
		return result, err
	}
	stored, err := store.load()
	if err != nil {
		return result, authStoreError(err)
	}
	accounts := stored.Accounts
	i := currentIndex(accounts, request.Active)
	switch operation {
	case "save":
		if err := validateStoredToken(request.Token); err != nil {
			return result, err
		}
		kept := accounts[:0]
		for _, account := range accounts {
			if account.UserID != request.Token.UserID {
				kept = append(kept, account)
			}
		}
		stored.Accounts = append(kept, *request.Token)
		save := func() error { return authStoreError(store.save(stored)) }
		if request.selectLocally {
			return result, saveWithSelection(request.Token.UserID, save)
		}
		return result, save()
	case "delete", "switch":
		if operation == "switch" || request.Login != "" {
			if i = indexOf(accounts, request.Login); i < 0 {
				return result, apperr.New(apperr.CodeInvalidArgument, fmt.Sprintf("not signed in as %q: run 'enbu auth login' to add the account", request.Login), nil)
			}
		}
		if operation == "delete" {
			if i < 0 {
				return result, nil
			}
			stored.Accounts = append(accounts[:i:i], accounts[i+1:]...)
			return result, authStoreError(store.save(stored))
		}
	case "list":
		for _, account := range accounts {
			result.Logins = append(result.Logins, account.Username)
		}
		if i >= 0 {
			result.Current = accounts[i].Username
		}
		return result, nil
	case "load":
	default:
		return result, errors.New("unknown GitHub credential operation")
	}
	if i < 0 {
		return result, notLoggedInError()
	}
	result.Token = &accounts[i]
	return result, nil
}

func indexOf(accounts []StoredToken, login string) int {
	for i, a := range accounts {
		if strings.EqualFold(a.Username, login) {
			return i
		}
	}
	return -1
}

func currentIndex(accounts []StoredToken, id int64) int {
	for i, a := range accounts {
		if a.UserID == id {
			return i
		}
	}
	return len(accounts) - 1
}

func parseAccounts(data []byte) ([]StoredToken, error) {
	var stored struct {
		Accounts json.RawMessage `json:"accounts"`
	}
	if err := decodeStrict(data, &stored); err != nil {
		return nil, err
	}
	var accounts []StoredToken
	if err := decodeStrict(stored.Accounts, &accounts); err != nil {
		return nil, err
	}
	return accounts, validateAccounts(accounts)
}

func validateAccounts(accounts []StoredToken) error {
	seen := make(map[int64]bool, len(accounts))
	for i := range accounts {
		if err := validateStoredToken(&accounts[i]); err != nil {
			return err
		}
		if seen[accounts[i].UserID] {
			return errors.New("duplicate GitHub account")
		}
		seen[accounts[i].UserID] = true
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
