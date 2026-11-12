package desktop

import (
	"context"
	"errors"
	"github.com/enbu-net/enbu/app"
	"github.com/enbu-net/enbu/pkg/apperr"
	"github.com/enbu-net/enbu/pkg/clock"
	"testing"
)

func TestBrowseRepositoryCancellationKeepsTheSelection(t *testing.T) {
	s := NewService(app.New(clock.New()))
	s.ctx = context.Background()
	s.repoPath = "existing"
	s.pickDir = func(context.Context) (string, error) { return "", nil }
	info, err := s.BrowseRepository()
	if err != nil || info.Path != "" || s.repoPath != "existing" {
		t.Fatalf("cancel returned %+v %v, selected %q", info, err, s.repoPath)
	}
}
func TestBrowseRepositoryStillReportsPickerFailures(t *testing.T) {
	s := NewService(app.New(clock.New()))
	s.ctx = context.Background()
	s.repoPath = "existing"
	s.pickDir = func(context.Context) (string, error) { return "", errors.New("synthetic native failure") }
	_, err := s.BrowseRepository()
	if !apperr.Is(err, apperr.CodeInternal) || s.repoPath != "existing" {
		t.Fatalf("failure returned %v, selected %q", err, s.repoPath)
	}
}
