package auth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestNewPKCE(t *testing.T) {
	verifier1, challenge1, err := newPKCE()
	if err != nil {
		t.Fatal(err)
	}
	verifier2, _, err := newPKCE()
	if err != nil {
		t.Fatal(err)
	}
	if verifier1 == verifier2 {
		t.Fatal("generated secrets were reused")
	}
	if len(verifier1) != 43 || len(challenge1) != 43 {
		t.Fatalf("unexpected lengths: verifier=%d challenge=%d", len(verifier1), len(challenge1))
	}
	verifierSum := sha256.Sum256([]byte(verifier1))
	if challenge1 != base64.RawURLEncoding.EncodeToString(verifierSum[:]) {
		t.Fatal("PKCE challenge is invalid")
	}
}

func TestCallbackRejectsInvalidRequestsThenAcceptsValidCallback(t *testing.T) {
	state := strings.Repeat("b", 64)
	results := make(chan callbackResult, 1)
	server := newCallbackServer(state, results)

	tests := []string{
		"?code=ok",
		"?code=ok&state=wrong",
		"?code=one&code=two&state=" + state,
		"?code=ok&state=" + state + "&state=" + state,
		"?code=" + strings.Repeat("x", maxOAuthCodeLength+1) + "&state=" + state,
	}
	for _, rawQuery := range tests {
		req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1"+callbackPath+rawQuery, nil)
		req.RemoteAddr = "127.0.0.1:12345"
		response := httptest.NewRecorder()
		server.Handler.ServeHTTP(response, req)
		if response.Code != http.StatusBadRequest {
			t.Fatalf("query %q returned %d", rawQuery, response.Code)
		}
		select {
		case <-results:
			t.Fatalf("query %q delivered a callback", rawQuery)
		default:
		}
	}

	req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1"+callbackPath+"?code=secret-code&state="+state, nil)
	req.RemoteAddr = "127.0.0.1:12345"
	response := httptest.NewRecorder()
	server.Handler.ServeHTTP(response, req)
	if response.Code != http.StatusOK {
		t.Fatalf("valid callback returned %d", response.Code)
	}
	result := <-results
	if result.code != "secret-code" || result.denied {
		t.Fatalf("unexpected callback result: %#v", result)
	}
	if strings.Contains(response.Body.String(), "secret-code") || strings.Contains(response.Body.String(), state) {
		t.Fatal("callback HTML leaked query values")
	}
	if !strings.Contains(response.Body.String(), `href="enbu://auth/complete"`) {
		t.Fatal("successful callback does not link back to the desktop app")
	}
	second := httptest.NewRecorder()
	server.Handler.ServeHTTP(second, req)
	if second.Code != http.StatusConflict {
		t.Fatalf("duplicate callback returned %d", second.Code)
	}
	for _, header := range []string{"Cache-Control", "Pragma", "Referrer-Policy", "X-Content-Type-Options"} {
		if response.Header().Get(header) == "" {
			t.Fatalf("missing callback header %s", header)
		}
	}
}

func TestCallbackRejectsNonLoopbackAndWrongMethod(t *testing.T) {
	state := strings.Repeat("b", 64)
	server := newCallbackServer(state, make(chan callbackResult, 1))
	for _, tc := range []struct {
		method string
		path   string
		remote string
	}{
		{http.MethodPost, callbackPath, "127.0.0.1:1234"},
		{http.MethodGet, "/wrong", "127.0.0.1:1234"},
		{http.MethodGet, callbackPath, "192.0.2.1:1234"},
		{http.MethodGet, callbackPath, "[::1]:1234"},
	} {
		req := httptest.NewRequest(tc.method, "http://127.0.0.1"+tc.path+"?code=x&state="+state, nil)
		req.RemoteAddr = tc.remote
		response := httptest.NewRecorder()
		server.Handler.ServeHTTP(response, req)
		if response.Code != http.StatusBadRequest {
			t.Fatalf("%#v returned %d", tc, response.Code)
		}
	}
}

func TestCallbackDenialDoesNotLeakDescription(t *testing.T) {
	state := strings.Repeat("a", 64)
	results := make(chan callbackResult, 1)
	server := newCallbackServer(state, results)
	req := httptest.NewRequest(
		http.MethodGet,
		"http://127.0.0.1"+callbackPath+"?error=access_denied&error_description=private&state="+state,
		nil,
	)
	req.RemoteAddr = "127.0.0.1:12345"
	response := httptest.NewRecorder()
	server.Handler.ServeHTTP(response, req)
	if response.Code != http.StatusOK || !((<-results).denied) {
		t.Fatalf("denial callback returned %d", response.Code)
	}
	if strings.Contains(response.Body.String(), "private") || strings.Contains(response.Body.String(), state) {
		t.Fatal("denial HTML leaked callback values")
	}
}

func TestOAuthLoginEndToEnd(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	stubBackend(t)
	originalUser := getGitHubUser
	getGitHubUser = func(context.Context, string) (string, int64, error) { return "octo", 123, nil }
	t.Cleanup(func() { getGitHubUser = originalUser })

	state := strings.Repeat("b", 64)
	var redirectURI string
	var challenge string
	var mu sync.Mutex
	broker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1/oauth/authorize":
			var body authorizeRequest
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Error(err)
			}
			mu.Lock()
			redirectURI = body.RedirectURI
			challenge = body.CodeChallenge
			mu.Unlock()
			if !strings.HasPrefix(redirectURI, "http://127.0.0.1:") {
				t.Errorf("redirect URI = %q", redirectURI)
			}
			authorizeURL := "https://github.com/login/oauth/authorize?" + url.Values{
				"state":                 {state},
				"code_challenge":        {body.CodeChallenge},
				"code_challenge_method": {"S256"},
				"redirect_uri":          {body.RedirectURI},
			}.Encode()
			_ = json.NewEncoder(w).Encode(authorizeResponse{
				AuthorizeURL: authorizeURL,
				State:        state,
			})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/oauth/exchange":
			var body exchangeRequest
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Error(err)
			}
			verifierSum := sha256.Sum256([]byte(body.CodeVerifier))
			if body.Code != "github-code" || body.RedirectURI != redirectURI ||
				base64.RawURLEncoding.EncodeToString(verifierSum[:]) != challenge {
				t.Errorf("invalid exchange request")
			}
			if r.Header.Get("Authorization") != "" {
				t.Error("exchange request unexpectedly used authorization header")
			}
			_ = json.NewEncoder(w).Encode(exchangeResponse{
				AccessToken: "github-token",
				TokenType:   "Bearer",
				Scope:       "repo,read:org,write:packages,read:packages",
			})
		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer broker.Close()

	client := newOAuthClient(broker.URL, broker.Client())
	token, err := client.login(context.Background(), func(string) error {
		mu.Lock()
		callbackURL := redirectURI
		mu.Unlock()
		response, err := http.Get(callbackURL + "?code=github-code&state=" + url.QueryEscape(state))
		if err == nil {
			_ = response.Body.Close()
		}
		return err
	})
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	if token.Username != "octo" || token.UserID != 123 || token.AccessToken != "github-token" {
		t.Fatalf("stored token = %#v", token)
	}
}

func TestOAuthLoginReturnsWhenBrowserFails(t *testing.T) {
	state := strings.Repeat("b", 64)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method != http.MethodPost || r.URL.Path != "/v1/oauth/authorize" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		var body authorizeRequest
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		_ = json.NewEncoder(w).Encode(authorizeResponse{
			AuthorizeURL: authorizeURL(state, body.CodeChallenge, body.RedirectURI),
			State:        state,
		})
	}))
	defer server.Close()

	client := newOAuthClient(server.URL, server.Client())
	_, err := client.login(context.Background(), func(string) error { return io.ErrClosedPipe })
	if err == nil || err.Error() != "opening browser failed" {
		t.Fatalf("login error = %v", err)
	}
}

func TestOAuthLoginCancellationWhileWaitingForCallback(t *testing.T) {
	state := strings.Repeat("d", 64)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method != http.MethodPost || r.URL.Path != "/v1/oauth/authorize" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		var body authorizeRequest
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		_ = json.NewEncoder(w).Encode(authorizeResponse{
			AuthorizeURL: authorizeURL(state, body.CodeChallenge, body.RedirectURI),
			State:        state,
		})
	}))
	defer server.Close()

	ctx, cancel := context.WithCancel(context.Background())
	client := newOAuthClient(server.URL, server.Client())
	_, err := client.login(ctx, func(string) error {
		cancel()
		return nil
	})
	if err == nil || !strings.Contains(err.Error(), context.Canceled.Error()) {
		t.Fatalf("login error = %v", err)
	}
}

func TestOAuthHTTPStagesHonorTimeouts(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(200 * time.Millisecond)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusGatewayTimeout)
	}))
	defer server.Close()

	httpClient := server.Client()
	httpClient.Timeout = 25 * time.Millisecond
	client := newOAuthClient(server.URL, httpClient)
	started := time.Now()
	_, err := client.authorize(context.Background(), authorizeRequest{})
	if err == nil || time.Since(started) > 150*time.Millisecond {
		t.Fatalf("authorization timeout err=%v elapsed=%s", err, time.Since(started))
	}

	started = time.Now()
	_, err = client.exchange(context.Background(), exchangeRequest{
		Code: "code", CodeVerifier: "verifier", RedirectURI: "http://127.0.0.1:1234/oauth/callback",
	})
	if err == nil || time.Since(started) > 150*time.Millisecond {
		t.Fatalf("exchange timeout err=%v elapsed=%s", err, time.Since(started))
	}
}

func TestOAuthErrorsDoNotExposeSecrets(t *testing.T) {
	secrets := []string{"authorization-code", "pkce-verifier", "redirect-uri", "access-token"}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadGateway)
		_, _ = io.WriteString(w, strings.Join(secrets, " "))
	}))
	defer server.Close()

	client := newOAuthClient(server.URL, server.Client())
	_, err := client.exchange(context.Background(), exchangeRequest{
		Code: secrets[0], CodeVerifier: secrets[1], RedirectURI: secrets[2],
	})
	if err == nil {
		t.Fatal("exchange unexpectedly succeeded")
	}
	for _, secret := range secrets {
		if strings.Contains(err.Error(), secret) {
			t.Fatalf("error leaked secret %q", secret)
		}
	}
}

func TestExchangeRetriesOnlyRateLimit(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		w.Header().Set("Content-Type", "application/json")
		if calls == 1 {
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		_ = json.NewEncoder(w).Encode(exchangeResponse{
			AccessToken: "token",
			TokenType:   "bearer",
			Scope:       "repo read:org write:packages read:packages",
		})
	}))
	defer server.Close()
	client := newOAuthClient(server.URL, server.Client())
	_, err := client.exchange(context.Background(), exchangeRequest{})
	if err != nil || calls != 2 {
		t.Fatalf("exchange err=%v calls=%d", err, calls)
	}

	calls = 0
	badGatewayServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer badGatewayServer.Close()
	client = newOAuthClient(badGatewayServer.URL, badGatewayServer.Client())
	_, err = client.exchange(context.Background(), exchangeRequest{})
	if err == nil || calls != 1 {
		t.Fatalf("5xx exchange err=%v calls=%d", err, calls)
	}
}

func TestRetryAfterAcceptsPastHTTPDate(t *testing.T) {
	now := time.Now()
	delay, ok := retryAfter(now.Add(-time.Second).UTC().Format(http.TimeFormat), now)
	if !ok || delay != 0 {
		t.Fatalf("retryAfter returned delay=%s ok=%v", delay, ok)
	}
}

func TestRetryDelayUsesBoundedExponentialMinimum(t *testing.T) {
	tests := []struct {
		serverDelay time.Duration
		attempt     int
		want        time.Duration
	}{
		{attempt: 0, want: 100 * time.Millisecond},
		{attempt: 1, want: 200 * time.Millisecond},
		{attempt: 20, want: 5 * time.Second},
		{serverDelay: 10 * time.Second, attempt: 20, want: 10 * time.Second},
	}
	for _, tt := range tests {
		if got := retryDelay(tt.serverDelay, tt.attempt); got != tt.want {
			t.Fatalf("retryDelay(%s, %d) = %s, want %s", tt.serverDelay, tt.attempt, got, tt.want)
		}
	}
}

func TestValidAuthorizeURLRequiresMatchingOAuthParameters(t *testing.T) {
	state := strings.Repeat("a", 64)
	challenge := strings.Repeat("b", 43)
	redirectURI := "http://127.0.0.1:1234/oauth/callback"
	base := "https://github.com/login/oauth/authorize"
	valid := authorizeURL(state, challenge, redirectURI)
	tests := []struct {
		name string
		url  string
		want bool
	}{
		{name: "valid", url: valid, want: true},
		{name: "missing", url: base},
		{name: "duplicate state", url: valid + "&state=" + state},
		{name: "mismatched state", url: strings.Replace(valid, state, "wrong", 1)},
		{name: "mismatched challenge", url: strings.Replace(valid, challenge, "wrong", 1)},
		{name: "mismatched redirect", url: strings.Replace(valid, url.QueryEscape(redirectURI), url.QueryEscape("http://127.0.0.1:4321/oauth/callback"), 1)},
		{name: "wrong method", url: strings.Replace(valid, "S256", "plain", 1)},
		{name: "wrong host", url: strings.Replace(valid, "github.com", "example.com", 1)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := validAuthorizeURL(tt.url, state, challenge, redirectURI); got != tt.want {
				t.Fatalf("validAuthorizeURL() = %v, want %v", got, tt.want)
			}
		})
	}
}

func authorizeURL(state, challenge, redirectURI string) string {
	return "https://github.com/login/oauth/authorize?" + url.Values{
		"state":                 {state},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
		"redirect_uri":          {redirectURI},
	}.Encode()
}

func TestValidateTokenRequiresBearerAndNormalizedScopes(t *testing.T) {
	valid := exchangeResponse{
		AccessToken: "token",
		TokenType:   "BEARER",
		Scope:       "repo read:org write:packages",
	}
	if err := validateToken(valid); err != nil {
		t.Fatalf("valid token rejected: %v", err)
	}
	for _, mutate := range []func(*exchangeResponse){
		func(token *exchangeResponse) { token.AccessToken = "" },
		func(token *exchangeResponse) { token.TokenType = "mac" },
		func(token *exchangeResponse) { token.Scope = "repo read:org read:packages" },
	} {
		token := valid
		mutate(&token)
		if err := validateToken(token); err == nil {
			t.Fatalf("invalid token accepted: %#v", token)
		}
	}
}

func TestDecodeJSONRejectsOversizeAndUnknownFields(t *testing.T) {
	for _, body := range []string{
		`{"access_token":"token","token_type":"bearer","scope":"repo","extra":true}`,
		`{"value":"` + strings.Repeat("x", maxResponseBytes) + `"}`,
	} {
		response := &http.Response{
			Header: http.Header{"Content-Type": []string{"application/json"}},
			Body:   io.NopCloser(strings.NewReader(body)),
		}
		var result exchangeResponse
		if err := decodeJSON(response, &result); err == nil {
			t.Fatalf("decodeJSON accepted invalid body")
		}
	}
}
