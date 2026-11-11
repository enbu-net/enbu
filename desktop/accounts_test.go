package desktop

import (
	"testing"

	"github.com/enbu-net/enbu/app"
	"github.com/enbu-net/enbu/pkg/apperr"
	"github.com/enbu-net/enbu/pkg/clock"
)

// memoryAccounts is an accountStore of the given logins.
type memoryAccounts struct {
	logins  []string
	current string
}

func (m *memoryAccounts) Accounts() ([]string, string, error) { return m.logins, m.current, nil }

func (m *memoryAccounts) index(login string) int {
	for i, l := range m.logins {
		if l == login {
			return i
		}
	}
	return -1
}

func (m *memoryAccounts) Switch(login string) error {
	if m.index(login) < 0 {
		return apperr.New(apperr.CodeInvalidArgument, "not signed in", nil)
	}
	m.current = login
	return nil
}

func (m *memoryAccounts) Delete(login string) error {
	if login == "" {
		login = m.current
	}
	i := m.index(login)
	if i < 0 {
		return apperr.New(apperr.CodeInvalidArgument, "not signed in", nil)
	}
	m.logins = append(m.logins[:i:i], m.logins[i+1:]...)
	if m.current == login {
		m.current = ""
	}
	return nil
}

func TestTheDesktopListsSwitchesAndSignsOutOfAccounts(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	t.Setenv("GITHUB_TOKEN", "")
	s := NewService(app.New(clock.New()))
	store := &memoryAccounts{logins: []string{"work", "home"}, current: "home"}
	s.accounts = store

	status := s.GetAuthStatus()
	if len(status.Accounts) != 2 || status.Accounts[0] != "work" || status.Accounts[1] != "home" {
		t.Fatalf("GetAuthStatus = %+v", status)
	}
	if err := s.SwitchAccount("work"); err != nil || store.current != "work" {
		t.Fatalf("SwitchAccount = %v, current %q", err, store.current)
	}
	if err := s.SwitchAccount("nobody"); !apperr.Is(err, apperr.CodeInvalidArgument) {
		t.Fatalf("SwitchAccount(unknown) = %v, want invalid_argument", err)
	}
	if err := s.Logout("home"); err != nil || len(store.logins) != 1 || store.current != "work" {
		t.Fatalf("Logout(home) = %v, store %+v", err, store)
	}
	if err := s.Logout(""); err != nil || len(store.logins) != 0 {
		t.Fatalf("Logout() = %v, store %+v", err, store)
	}
}
