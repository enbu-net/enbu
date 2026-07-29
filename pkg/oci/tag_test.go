package oci

import (
	"strings"
	"testing"
)

func TestCleanTag(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"user-abc123", "user-abc123"},
		{"user@host", "user-host"},
		{"a/b/c", "a-b-c"},
		{strings.Repeat("x", 200), strings.Repeat("x", 128)},
	}

	for _, tt := range tests {
		got := CleanTag(tt.input)
		if got != tt.want {
			t.Errorf("CleanTag(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}
