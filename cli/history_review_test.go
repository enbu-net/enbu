package cli

import (
	"testing"

	"github.com/enbu-net/enbu/app"
	"github.com/enbu-net/enbu/pkg/apperr"
)

func TestHistoryReviewRejectsAnEmptyAcceptanceBaseline(t *testing.T) {
	cmd := newHistoryCommand(&app.App{})
	cmd.SetArgs([]string{"review", "--accept=", "sha256:unused"})
	if err := cmd.ExecuteContext(t.Context()); !apperr.Is(err, apperr.CodeInvalidArgument) {
		t.Fatalf("empty acceptance baseline: %v", err)
	}
}
