package auth

import (
	"path/filepath"
	"reflect"
	"testing"
)

func TestBrowserCommandPreservesOAuthURL(t *testing.T) {
	url := "https://github.com/login/oauth/authorize?client_id=id&state=state&code_challenge=challenge"
	tests := []struct {
		goos string
		want []string
	}{
		{goos: "darwin", want: []string{"/usr/bin/open", url}},
		{goos: "windows", want: []string{filepath.Join(systemDirectory(), "rundll32.exe"), "url.dll,FileProtocolHandler", url}},
		{goos: "linux", want: []string{"xdg-open", url}},
	}
	for _, tt := range tests {
		t.Run(tt.goos, func(t *testing.T) {
			if got := browserCommand(tt.goos, url).Args; !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("browser command = %#v, want %#v", got, tt.want)
			}
		})
	}
}
