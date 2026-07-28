package auth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/enbu-net/enbu/apperr"
)

func TestDeviceLoginEndToEnd(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	stubBackend(t)
	originalUser := getGitHubUser
	getGitHubUser = func(_ context.Context, token string) (string, int64, error) {
		if token != "github-token" {
			t.Fatalf("GitHub token = %q", token)
		}
		return "octo", 123, nil
	}
	t.Cleanup(func() { getGitHubUser = originalUser })

	var tokenRequests int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Header.Get("Accept") != "application/json" {
			t.Errorf("Accept = %q", r.Header.Get("Accept"))
		}
		if err := r.ParseForm(); err != nil {
			t.Error(err)
		}
		switch r.URL.Path {
		case "/device/code":
			assertFormValue(t, r.Form, "client_id", "client-id")
			assertFormValue(t, r.Form, "scope", deviceScopes)
			_ = json.NewEncoder(w).Encode(deviceCodeResponse{
				DeviceCode:      "device-code",
				UserCode:        "ABCD-1234",
				VerificationURI: githubDeviceURL,
				ExpiresIn:       900,
				Interval:        5,
			})
		case "/access_token":
			tokenRequests++
			assertFormValue(t, r.Form, "client_id", "client-id")
			assertFormValue(t, r.Form, "device_code", "device-code")
			assertFormValue(t, r.Form, "grant_type", deviceGrantType)
			switch tokenRequests {
			case 1:
				_ = json.NewEncoder(w).Encode(deviceTokenResponse{Error: "authorization_pending"})
			case 2:
				_ = json.NewEncoder(w).Encode(deviceTokenResponse{Error: "slow_down", Interval: 12})
			default:
				_ = json.NewEncoder(w).Encode(deviceTokenResponse{
					AccessToken: "github-token",
					TokenType:   "bearer",
					Scope:       "repo,read:org,write:packages",
				})
			}
		default:
			t.Errorf("unexpected request path %q", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	var waits []time.Duration
	client := &deviceFlowClient{
		deviceCodeURL: server.URL + "/device/code",
		tokenURL:      server.URL + "/access_token",
		http:          server.Client(),
		wait: func(_ context.Context, duration time.Duration) error {
			waits = append(waits, duration)
			return nil
		},
	}
	var prompted DeviceAuthorization
	token, err := client.login(context.Background(), "client-id", func(device DeviceAuthorization) error {
		prompted = device
		return nil
	})
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	if prompted.UserCode != "ABCD-1234" || prompted.VerificationURI != githubDeviceURL {
		t.Fatalf("prompt = %#v", prompted)
	}
	if token.Username != "octo" || token.UserID != 123 || token.AccessToken != "github-token" {
		t.Fatalf("stored token = %#v", token)
	}
	if want := []time.Duration{5 * time.Second, 5 * time.Second, 12 * time.Second}; !slices.Equal(waits, want) {
		t.Fatalf("poll waits = %v, want %v", waits, want)
	}
}

func TestDeviceLoginErrors(t *testing.T) {
	tests := []struct {
		name     string
		response deviceTokenResponse
		want     error
		wantCode apperr.Code
	}{
		{name: "access denied", response: deviceTokenResponse{Error: "access_denied"}, wantCode: apperr.CodeAccessDenied},
		{name: "expired", response: deviceTokenResponse{Error: "expired_token"}, wantCode: apperr.CodeAuthExpired},
		{name: "disabled", response: deviceTokenResponse{Error: "device_flow_disabled"}, want: errors.New("not enabled")},
		{
			name: "unknown",
			response: deviceTokenResponse{
				Error:            "future_error",
				ErrorDescription: "new failure",
			},
			want: errors.New(`"future_error" ("new failure")`),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := newDeviceFlowServer(t, tt.response)
			defer server.Close()
			client := &deviceFlowClient{
				deviceCodeURL: server.URL + "/device/code",
				tokenURL:      server.URL + "/access_token",
				http:          server.Client(),
				wait:          func(context.Context, time.Duration) error { return nil },
			}
			_, err := client.login(context.Background(), "client-id", func(DeviceAuthorization) error {
				return nil
			})
			if tt.wantCode != "" {
				if !apperr.Is(err, tt.wantCode) {
					t.Fatalf("error = %v, want code %q", err, tt.wantCode)
				}
				return
			}
			if err == nil || !contains(err.Error(), tt.want.Error()) {
				t.Fatalf("error = %v, want containing %q", err, tt.want)
			}
		})
	}
}

func TestDeviceLoginReportsExpiredWhenDeviceDeadlineElapses(t *testing.T) {
	server := newDeviceFlowServer(t, deviceTokenResponse{})
	defer server.Close()
	client := &deviceFlowClient{
		deviceCodeURL: server.URL + "/device/code",
		tokenURL:      server.URL + "/access_token",
		http:          server.Client(),
		wait: func(context.Context, time.Duration) error {
			return context.DeadlineExceeded
		},
	}
	_, err := client.login(context.Background(), "client-id", func(DeviceAuthorization) error { return nil })
	if !apperr.Is(err, apperr.CodeAuthExpired) {
		t.Fatalf("error = %v, want code %q", err, apperr.CodeAuthExpired)
	}
}

func TestDeviceLoginHonorsCancellationBeforePolling(t *testing.T) {
	server := newDeviceFlowServer(t, deviceTokenResponse{})
	defer server.Close()
	client := &deviceFlowClient{
		deviceCodeURL: server.URL + "/device/code",
		tokenURL:      server.URL + "/access_token",
		http:          server.Client(),
		wait: func(ctx context.Context, _ time.Duration) error {
			<-ctx.Done()
			return ctx.Err()
		},
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := client.login(ctx, "client-id", func(DeviceAuthorization) error { return nil })
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context canceled", err)
	}
}

func newDeviceFlowServer(t *testing.T, tokenResponse deviceTokenResponse) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/device/code":
			_ = json.NewEncoder(w).Encode(deviceCodeResponse{
				DeviceCode:      "device-code",
				UserCode:        "ABCD-1234",
				VerificationURI: githubDeviceURL,
				ExpiresIn:       900,
				Interval:        5,
			})
		case "/access_token":
			_ = json.NewEncoder(w).Encode(tokenResponse)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}

func assertFormValue(t *testing.T, values url.Values, key, want string) {
	t.Helper()
	if got := values.Get(key); got != want {
		t.Errorf("%s = %q, want %q", key, got, want)
	}
}

func contains(value, substring string) bool {
	return len(substring) <= len(value) && strings.Contains(value, substring)
}
