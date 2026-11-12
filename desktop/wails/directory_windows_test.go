package main

import (
	"context"
	"errors"
	"fmt"
	"github.com/ncruces/zenity"
	"testing"
)

func TestSelectDirectoryCancellationAndErrors(t *testing.T) {
	for _, tc := range []struct {
		name, path string
		err        error
		want       string
		wantErr    bool
	}{
		{"cancel", "", zenity.ErrCanceled, "", false},
		{"wrapped cancel", "", fmt.Errorf("dialog: %w", zenity.ErrCanceled), "", false},
		{"failure", "", errors.New("synthetic failure"), "", true},
		{"folder", `C:\日本語\project`, nil, `C:\日本語\project`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := selectDirectory(context.Background(), 0, func(...zenity.Option) (string, error) { return tc.path, tc.err })
			if got != tc.want || (err != nil) != tc.wantErr {
				t.Fatalf("got %q %v", got, err)
			}
			if tc.wantErr && !errors.Is(err, tc.err) {
				t.Fatal("lost actual error")
			}
		})
	}
}
