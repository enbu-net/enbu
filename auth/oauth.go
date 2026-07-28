package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/enbu-net/enbu/apperr"
	gh "github.com/enbu-net/enbu/provider/github"
)

const (
	authEndpoint       = "https://auth.enbu-net.workers.dev"
	callbackPath       = "/oauth/callback"
	loginTimeout       = 10 * time.Minute
	maxResponseBytes   = 4 * 1024
	maxOAuthCodeLength = 1024
	retryBackoffStart  = 100 * time.Millisecond
	retryBackoffMax    = 5 * time.Second
)

var (
	statePattern = regexp.MustCompile(`^[a-f0-9]{64}$`)

	getGitHubUser = func(ctx context.Context, token string) (string, int64, error) {
		user, err := gh.NewClient(token).GetUser(ctx)
		if err != nil {
			return "", 0, err
		}
		return user.Login, user.ID, nil
	}
)

type BrowserOpener func(string) error

type oauthClient struct {
	baseURL string
	http    *http.Client
}

type authorizeRequest struct {
	CodeChallenge string `json:"code_challenge"`
	RedirectURI   string `json:"redirect_uri"`
}

type authorizeResponse struct {
	AuthorizeURL string `json:"authorize_url"`
	State        string `json:"state"`
}

type exchangeRequest struct {
	Code         string `json:"code"`
	CodeVerifier string `json:"code_verifier"`
	RedirectURI  string `json:"redirect_uri"`
}

type exchangeResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	Scope       string `json:"scope"`
}

type callbackResult struct {
	code   string
	denied bool
}

func Login(ctx context.Context, openBrowser BrowserOpener) (*StoredToken, error) {
	return newOAuthClient(authEndpoint, newHTTPClient()).login(ctx, openBrowser)
}

func newOAuthClient(baseURL string, httpClient *http.Client) *oauthClient {
	return &oauthClient{baseURL: strings.TrimRight(baseURL, "/"), http: httpClient}
}

func newHTTPClient() *http.Client {
	dialer := &net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}
	return &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			Proxy:                 http.ProxyFromEnvironment,
			DialContext:           dialer.DialContext,
			TLSHandshakeTimeout:   5 * time.Second,
			ResponseHeaderTimeout: 10 * time.Second,
		},
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func (c *oauthClient) login(parent context.Context, openBrowser BrowserOpener) (*StoredToken, error) {
	ctx, cancel := context.WithTimeout(parent, loginTimeout)
	defer cancel()

	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("starting OAuth callback listener: %w", err)
	}
	defer func() { _ = listener.Close() }()

	port := listener.Addr().(*net.TCPAddr).Port
	redirectURI := fmt.Sprintf("http://127.0.0.1:%d%s", port, callbackPath)
	verifier, challenge, err := newPKCE()
	if err != nil {
		return nil, err
	}

	authorization, err := c.authorize(ctx, authorizeRequest{
		CodeChallenge: challenge,
		RedirectURI:   redirectURI,
	})
	if err != nil {
		return nil, err
	}

	callbackCh := make(chan callbackResult, 1)
	server := newCallbackServer(authorization.State, callbackCh)
	serveErr := make(chan error, 1)
	go func() {
		if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serveErr <- err
		}
	}()
	defer func() { _ = server.Close() }()

	if openBrowser == nil {
		return nil, errors.New("opening browser: browser opener is unavailable")
	}
	if err := openBrowser(authorization.AuthorizeURL); err != nil {
		return nil, errors.New("opening browser failed")
	}

	var callback callbackResult
	select {
	case <-ctx.Done():
		return nil, fmt.Errorf("waiting for OAuth callback: %w", ctx.Err())
	case err := <-serveErr:
		return nil, fmt.Errorf("serving OAuth callback: %w", err)
	case callback = <-callbackCh:
	}
	if callback.denied {
		return nil, apperr.New(apperr.CodeAccessDenied, "access denied by user", nil)
	}

	token, err := c.exchange(ctx, exchangeRequest{
		Code:         callback.code,
		CodeVerifier: verifier,
		RedirectURI:  redirectURI,
	})
	if err != nil {
		return nil, err
	}

	login, userID, err := getGitHubUser(ctx, token.AccessToken)
	if err != nil {
		return nil, fmt.Errorf("getting GitHub user: %w", err)
	}
	if login == "" || userID <= 0 {
		return nil, errors.New("getting GitHub user: invalid identity response")
	}

	stored := &StoredToken{AccessToken: token.AccessToken, Username: login, UserID: userID}
	if err := SaveToken(stored); err != nil {
		return nil, fmt.Errorf("saving token: %w", err)
	}
	return stored, nil
}

func newPKCE() (verifier, challenge string, err error) {
	verifierBytes := make([]byte, 32)
	if _, err = rand.Read(verifierBytes); err != nil {
		return "", "", fmt.Errorf("generating PKCE verifier: %w", err)
	}

	verifier = base64.RawURLEncoding.EncodeToString(verifierBytes)
	challengeSum := sha256.Sum256([]byte(verifier))
	challenge = base64.RawURLEncoding.EncodeToString(challengeSum[:])
	return verifier, challenge, nil
}

func (c *oauthClient) authorize(ctx context.Context, body authorizeRequest) (*authorizeResponse, error) {
	var result authorizeResponse
	if err := c.doJSON(ctx, http.MethodPost, "/v1/oauth/authorize", body, http.StatusOK, &result); err != nil {
		return nil, fmt.Errorf("requesting OAuth authorization: %w", err)
	}
	if !statePattern.MatchString(result.State) {
		return nil, errors.New("requesting OAuth authorization: invalid state")
	}
	if !validAuthorizeURL(result.AuthorizeURL, result.State, body.CodeChallenge, body.RedirectURI) {
		return nil, errors.New("requesting OAuth authorization: invalid authorize URL")
	}
	return &result, nil
}

func validAuthorizeURL(raw, expectedState, expectedChallenge, expectedRedirectURI string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host != "github.com" ||
		u.Path != "/login/oauth/authorize" || u.User != nil || u.Fragment != "" {
		return false
	}
	query := u.Query()
	state, stateOK := singleValue(query, "state", len(expectedState))
	challenge, challengeOK := singleValue(query, "code_challenge", len(expectedChallenge))
	redirectURI, redirectOK := singleValue(query, "redirect_uri", len(expectedRedirectURI))
	method, methodOK := singleValue(query, "code_challenge_method", len("S256"))
	return stateOK && subtle.ConstantTimeCompare([]byte(state), []byte(expectedState)) == 1 &&
		challengeOK && subtle.ConstantTimeCompare([]byte(challenge), []byte(expectedChallenge)) == 1 &&
		redirectOK && subtle.ConstantTimeCompare([]byte(redirectURI), []byte(expectedRedirectURI)) == 1 &&
		methodOK && method == "S256"
}

func (c *oauthClient) exchange(ctx context.Context, body exchangeRequest) (*exchangeResponse, error) {
	retryAttempt := 0
	for {
		var result exchangeResponse
		resp, err := c.requestJSON(ctx, http.MethodPost, "/v1/oauth/exchange", body)
		if err != nil {
			return nil, fmt.Errorf("exchanging OAuth code: %w", err)
		}
		if resp.StatusCode == http.StatusTooManyRequests {
			delay, ok := retryAfter(resp.Header.Get("Retry-After"), time.Now())
			_ = resp.Body.Close()
			delay = retryDelay(delay, retryAttempt)
			retryAttempt++
			deadline, hasDeadline := ctx.Deadline()
			if !ok || hasDeadline && !time.Now().Add(delay).Before(deadline) {
				return nil, errors.New("exchanging OAuth code: rate limited")
			}
			timer := time.NewTimer(delay)
			select {
			case <-ctx.Done():
				timer.Stop()
				return nil, fmt.Errorf("exchanging OAuth code: %w", ctx.Err())
			case <-timer.C:
			}
			continue
		}
		if resp.StatusCode != http.StatusOK {
			_ = resp.Body.Close()
			return nil, fmt.Errorf("exchanging OAuth code: unexpected status %d", resp.StatusCode)
		}
		if err := decodeJSON(resp, &result); err != nil {
			return nil, fmt.Errorf("exchanging OAuth code: %w", err)
		}
		if err := validateToken(result); err != nil {
			return nil, fmt.Errorf("exchanging OAuth code: %w", err)
		}
		return &result, nil
	}
}

func retryDelay(serverDelay time.Duration, attempt int) time.Duration {
	minimum := retryBackoffStart
	for range attempt {
		if minimum >= retryBackoffMax/2 {
			minimum = retryBackoffMax
			break
		}
		minimum *= 2
	}
	if serverDelay > minimum {
		return serverDelay
	}
	return minimum
}

func validateToken(token exchangeResponse) error {
	if token.AccessToken == "" || len(token.AccessToken) > 2048 {
		return errors.New("invalid access token")
	}
	if !strings.EqualFold(token.TokenType, "bearer") {
		return errors.New("unsupported token type")
	}
	if len(token.Scope) > 4096 {
		return errors.New("invalid scope")
	}
	got := make(map[string]bool)
	for scope := range strings.FieldsFuncSeq(token.Scope, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t' || r == '\n'
	}) {
		got[scope] = true
	}
	for _, required := range []string{"repo", "read:org", "write:packages"} {
		if !got[required] {
			return fmt.Errorf("missing required scope %q", required)
		}
	}
	return nil
}

func (c *oauthClient) doJSON(
	ctx context.Context,
	method, path string,
	body any,
	wantStatus int,
	result any,
) error {
	resp, err := c.requestJSON(ctx, method, path, body)
	if err != nil {
		return err
	}
	if resp.StatusCode != wantStatus {
		_ = resp.Body.Close()
		return fmt.Errorf("unexpected status %d", resp.StatusCode)
	}
	return decodeJSON(resp, result)
}

func (c *oauthClient) requestJSON(
	ctx context.Context,
	method, path string,
	body any,
) (*http.Response, error) {
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		reader = strings.NewReader(string(encoded))
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, reader)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")
	return c.http.Do(req)
}

func decodeJSON(resp *http.Response, result any) error {
	defer func() { _ = resp.Body.Close() }()
	mediaType, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return errors.New("invalid response content type")
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return errors.New("reading response")
	}
	if len(data) > maxResponseBytes {
		return errors.New("response body is too large")
	}
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(result); err != nil {
		return errors.New("invalid JSON response")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("invalid JSON response")
	}
	return nil
}

func retryAfter(value string, now time.Time) (time.Duration, bool) {
	if seconds, err := strconv.Atoi(value); err == nil && seconds >= 0 {
		return time.Duration(seconds) * time.Second, true
	}
	when, err := http.ParseTime(value)
	if err != nil {
		return 0, false
	}
	if when.Before(now) {
		return 0, true
	}
	return when.Sub(now), true
}

func newCallbackServer(expectedState string, result chan<- callbackResult) *http.Server {
	var once sync.Once
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		setCallbackHeaders(w)
		if !validCallbackRequest(r) {
			writeCallback(w, http.StatusBadRequest, false)
			return
		}
		query := r.URL.Query()
		states, stateOK := singleValue(query, "state", len(expectedState))
		if !stateOK || subtle.ConstantTimeCompare([]byte(states), []byte(expectedState)) != 1 {
			writeCallback(w, http.StatusBadRequest, false)
			return
		}
		if errorValue, ok := singleValue(query, "error", 256); ok {
			if _, hasCode := query["code"]; hasCode {
				writeCallback(w, http.StatusBadRequest, false)
				return
			}
			delivered := false
			once.Do(func() {
				delivered = true
				result <- callbackResult{denied: errorValue != ""}
			})
			if !delivered {
				writeCallback(w, http.StatusConflict, false)
				return
			}
			writeCallback(w, http.StatusOK, true)
			return
		}
		if _, hasError := query["error"]; hasError {
			writeCallback(w, http.StatusBadRequest, false)
			return
		}
		code, ok := singleValue(query, "code", maxOAuthCodeLength)
		if !ok {
			writeCallback(w, http.StatusBadRequest, false)
			return
		}
		delivered := false
		once.Do(func() {
			delivered = true
			result <- callbackResult{code: code}
		})
		if !delivered {
			writeCallback(w, http.StatusConflict, false)
			return
		}
		writeCallback(w, http.StatusOK, true)
	})
	return &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		MaxHeaderBytes:    8 * 1024,
	}
}

func validCallbackRequest(r *http.Request) bool {
	if r.Method != http.MethodGet || r.URL.Path != callbackPath {
		return false
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.To4() != nil && ip.IsLoopback()
}

func singleValue(values url.Values, key string, maxLength int) (string, bool) {
	items, ok := values[key]
	returnValue := ""
	if ok && len(items) == 1 {
		returnValue = items[0]
	}
	return returnValue, ok && len(items) == 1 && returnValue != "" && len(returnValue) <= maxLength
}

func setCallbackHeaders(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
}

func writeCallback(w http.ResponseWriter, status int, success bool) {
	w.WriteHeader(status)
	if success {
		_, _ = io.WriteString(w, `<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>enbu</title><body><main><h1>Authentication complete</h1><p>You can return to enbu.</p><p><a href="enbu://auth/complete">Open enbu desktop</a></p></main></body></html>`)
		return
	}
	_, _ = io.WriteString(w, "<!doctype html><title>enbu</title><p>Invalid authentication callback.</p>")
}
