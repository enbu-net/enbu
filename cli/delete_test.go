package cli

import (
	"testing"

	"github.com/enbu-net/enbu/app/apptest"
)

type deleteTestTokenProvider struct{}

func (*deleteTestTokenProvider) LoadToken() (string, string, error) { return "token", "alice", nil }

type deleteTestRepoDetector struct{}

func (*deleteTestRepoDetector) LoadRepo() (string, string, error) { return "owner", "repo", nil }

func TestDeleteCommandPassesBaseDigestToPush(t *testing.T) {
	a, rec := newSeededApp(t, map[string]string{"API_KEY": "secret"})
	cmd := NewWithApp("test", a)
	cmd.SetArgs([]string{"delete", "API_KEY"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("delete: %v", err)
	}
	puts := rec.secretPuts()
	if len(puts) != 2 {
		t.Fatalf("expected 2 push (main + snapshot), got %d", len(puts))
	}
	if puts[0].expected == "" || puts[0].expected != puts[0].lastRead {
		t.Fatalf("push must be based on the version that was read: expected=%q read=%q", puts[0].expected, puts[0].lastRead)
	}
	if got := secretsOf(t, a); len(got) != 0 {
		t.Fatalf("secret not deleted: %v", got)
	}
}

type staticKeyStore struct {
	apptest.Signers
	key []byte
}

func (s *staticKeyStore) storeSecret(_, _ string, value []byte) error {
	s.key = value
	return nil
}

func (s *staticKeyStore) loadSecret(string, string) ([]byte, error) {
	return s.key, nil
}
