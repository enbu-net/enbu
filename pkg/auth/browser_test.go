package auth

import (
	"reflect"
	"testing"
)

func TestBrowserCommandPreservesOAuthURL(t *testing.T) {
	url := "https://github.com/login/oauth/authorize?client_id=id&state=state&code_challenge=challenge"
	tests := []struct {
		goos string
		want []string
	}{
		{goos: "darwin", want: []string{"open", url}},
		{goos: "windows", want: []string{"rundll32", "url.dll,FileProtocolHandler", url}},
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
