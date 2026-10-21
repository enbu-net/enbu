package app

import "testing"

func mustSecrets(t *testing.T, a *App, env string) map[string]string {
	t.Helper()
	got, err := a.ListSecrets(bg, env)
	if err != nil {
		t.Fatal(err)
	}
	return got
}
