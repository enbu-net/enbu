package desktop

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/enbu-net/enbu/pkg/apperr"
	"github.com/enbu-net/enbu/pkg/auth"
	"github.com/enbu-net/enbu/pkg/clock"
	"github.com/enbu-net/enbu/pkg/config"
)

type AuthStatus struct {
	Authenticated       bool   `json:"authenticated"`
	WorkspaceConfigured bool   `json:"workspace_configured"`
	Username            string `json:"username,omitempty"`
	// Accounts are the signed-in GitHub logins, the most recent sign-in last;
	// Username is the one in use. GITHUB_TOKEN is not among them.
	Accounts []string  `json:"accounts,omitempty"`
	Repo     *RepoInfo `json:"repo,omitempty"`
}

type OAuthStart struct {
	SessionID string    `json:"session_id"`
	ExpiresAt time.Time `json:"expires_at"`
}

type OAuthStatus struct {
	State    string          `json:"state"`
	Error    *apperr.Payload `json:"error,omitempty"`
	Username string          `json:"username,omitempty"`
}

func (s *Service) GetAuthStatus() AuthStatus {
	var status AuthStatus
	s.repoMu.Lock()
	path := s.repoPath
	s.repoMu.Unlock()
	if path != "" {
		if cfg, err := config.LoadProjectFrom(path); err == nil {
			status.WorkspaceConfigured = cfg.Storage.URL != "" && !strings.HasPrefix(cfg.Storage.URL, "oci://ghcr.io/")
		}
	}
	if logins, _, err := s.accounts.Accounts(); err == nil {
		status.Accounts = logins
	}
	token, err := auth.LoadToken()
	if err != nil {
		slog.Debug("GetAuthStatus: not authenticated", "err", err)
		return status
	}
	status.Authenticated = true
	status.Username = token.Username
	if repo, err := s.GetRepoStatus(); err == nil && repo.Owner != "" {
		status.Repo = &repo
	}
	slog.Info("GetAuthStatus", "authenticated", status.Authenticated, "username", status.Username, "repo", status.Repo)
	return status
}

func (s *Service) StartOAuthLogin() (_ OAuthStart, err error) {
	defer publicInto(&err)
	slog.Info("StartOAuthLogin called")
	sessionID, err := randomSessionID()
	if err != nil {
		return OAuthStart{}, err
	}
	expiresAt := s.clock.Now().Add(10 * time.Minute)
	loginCtx, cancel := clock.WithDeadline(s.context(), s.clock, expiresAt)
	opened := make(chan struct{}, 1)
	finished := make(chan struct{})
	s.authMu.Lock()
	for _, session := range s.sessions {
		session.cancel()
	}
	s.sessions = map[string]*oauthSession{
		sessionID: {
			cancel:    cancel,
			expiresAt: expiresAt,
			status:    OAuthStatus{State: "pending"},
		},
	}
	s.authMu.Unlock()

	go func() {
		defer close(finished)
		defer cancel()
		token, err := s.authLogin(loginCtx, func(authorizeURL string) error {
			if s.openURL == nil {
				return errors.New("browser opener is unavailable")
			}
			if err := s.openURL(authorizeURL); err != nil {
				return err
			}
			opened <- struct{}{}
			return nil
		})
		if err != nil {
			slog.Error("OAuth login failed", "session_id", sessionID, "err", err)
			state := "error"
			payload := apperr.PayloadOf(err)
			if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
				state = "expired"
				payload = apperr.PayloadOf(apperr.New(apperr.CodeAuthExpired, "login session expired", nil))
			} else if apperr.Is(err, apperr.CodeAccessDenied) {
				state = "denied"
			}
			s.setOAuthStatus(sessionID, OAuthStatus{State: state, Error: &payload})
			return
		}
		s.setOAuthStatus(sessionID, OAuthStatus{State: "success", Username: token.Username})
	}()

	select {
	case <-opened:
		return OAuthStart{SessionID: sessionID, ExpiresAt: expiresAt}, nil
	case <-finished:
		status := s.GetOAuthLoginStatus(sessionID)
		if status.State == "success" {
			return OAuthStart{SessionID: sessionID, ExpiresAt: expiresAt}, nil
		}
		if status.Error == nil {
			return OAuthStart{}, errors.New("OAuth login failed")
		}
		return OAuthStart{}, apperr.New(status.Error.Code, status.Error.Message, status.Error.Params)
	case <-s.context().Done():
		cancel()
		return OAuthStart{}, s.context().Err()
	}
}

func (s *Service) GetOAuthLoginStatus(sessionID string) OAuthStatus {
	s.authMu.Lock()
	defer s.authMu.Unlock()
	session, ok := s.sessions[sessionID]
	if !ok {
		payload := apperr.PayloadOf(apperr.New(apperr.CodeAuthExpired, "login session expired", nil))
		return OAuthStatus{State: "expired", Error: &payload}
	}
	if !s.clock.Now().Before(session.expiresAt) && session.status.State == "pending" {
		session.cancel()
		payload := apperr.PayloadOf(apperr.New(apperr.CodeAuthExpired, "login session expired", nil))
		session.status = OAuthStatus{State: "expired", Error: &payload}
	}
	return session.status
}

func (s *Service) CancelOAuthLogin(sessionID string) {
	s.authMu.Lock()
	defer s.authMu.Unlock()
	session, ok := s.sessions[sessionID]
	if !ok {
		return
	}
	session.cancel()
	delete(s.sessions, sessionID)
}

func (s *Service) setOAuthStatus(sessionID string, status OAuthStatus) {
	s.authMu.Lock()
	defer s.authMu.Unlock()
	if session, ok := s.sessions[sessionID]; ok && session.status.State == "pending" {
		if !s.clock.Now().Before(session.expiresAt) {
			payload := apperr.PayloadOf(apperr.New(apperr.CodeAuthExpired, "login session expired", nil))
			session.status = OAuthStatus{State: "expired", Error: &payload}
		} else {
			session.status = status
		}
	}
}

// Logout signs out of the GitHub account login, or of the one in use when
// login is "". Signing out of the one in use moves to the most recent
// remaining sign-in.
func (s *Service) Logout(login string) error {
	return publicError(s.accounts.Delete(login))
}

func randomSessionID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("generating login session ID: %w", err)
	}
	return hex.EncodeToString(b[:]), nil
}

// accountStore holds the signed-in GitHub accounts; tests replace it.
type accountStore interface {
	Accounts() (logins []string, current string, err error)
	Switch(login string) error
	Delete(login string) error
}

// keyringAccounts is the accountStore of the OS keyring and the data directory.
type keyringAccounts struct{}

func (keyringAccounts) Accounts() ([]string, string, error) { return auth.Accounts() }

func (keyringAccounts) Switch(login string) error {
	_, err := auth.SwitchAccount(login)
	return err
}

func (keyringAccounts) Delete(login string) error { return auth.DeleteAccount(login) }

// SwitchAccount uses another signed-in GitHub account in this data directory.
func (s *Service) SwitchAccount(login string) error {
	return publicError(s.accounts.Switch(login))
}
