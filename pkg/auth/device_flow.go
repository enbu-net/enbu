package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	gh "github.com/enbu-net/enbu/pkg/provider/github"

	"github.com/enbu-net/enbu/pkg/apperr"
	"github.com/enbu-net/enbu/pkg/clock"
)

const (
	deviceGrantType    = "urn:ietf:params:oauth:grant-type:device_code"
	deviceScopes       = "repo read:org write:packages"
	maxDeviceValueSize = 2048
	maxResponseBytes   = 4 * 1024
	// defaultClientID is enbu's public GitHub OAuth app; ENBU_CLIENT_ID
	// overrides it.
	defaultClientID = "Ov23li6nFmfdF4FW9ikd"
)

var (
	// Keep these private while allowing E2E builds to route the complete device
	// flow through a local stub with linker flags.
	githubDeviceCodeURL = "https://github.com/login/device/code"
	githubTokenURL      = "https://github.com/login/oauth/access_token"
	githubDeviceURL     = "https://github.com/login/device"
)

type DeviceAuthorization struct {
	UserCode        string
	VerificationURI string
}

type DevicePrompter func(DeviceAuthorization) error

// Client signs in to GitHub with the Device Flow: the user enters a code at
// github.com/login/device, so no callback server or broker is involved.
type Client struct {
	Clock clock.Clock
}

var getGitHubUser = func(ctx context.Context, token string) (string, int64, error) {
	user, err := gh.NewClient(token).GetUser(ctx)
	if err != nil {
		return "", 0, err
	}
	return user.Login, user.ID, nil
}

type deviceFlowClient struct {
	clock         clock.Clock
	deviceCodeURL string
	tokenURL      string
	http          *http.Client
	wait          func(context.Context, time.Duration) error
}

type deviceCodeResponse struct {
	DeviceCode      string `json:"device_code"`
	UserCode        string `json:"user_code"`
	VerificationURI string `json:"verification_uri"`
	ExpiresIn       int    `json:"expires_in"`
	Interval        int    `json:"interval"`
}

type deviceTokenResponse struct {
	AccessToken      string `json:"access_token"`
	TokenType        string `json:"token_type"`
	Scope            string `json:"scope"`
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
	ErrorURI         string `json:"error_uri"`
	Interval         int    `json:"interval"`
}

// Login shows prompt the code to enter, waits for the user to authorize it and
// saves the token.
func (c Client) Login(ctx context.Context, prompt DevicePrompter) (*StoredToken, error) {
	if c.Clock == nil {
		c.Clock = clock.New()
	}
	client := &deviceFlowClient{
		clock:         c.Clock,
		deviceCodeURL: githubDeviceCodeURL,
		tokenURL:      githubTokenURL,
		http:          newHTTPClient(),
		wait:          func(ctx context.Context, d time.Duration) error { return clock.Wait(ctx, c.Clock, d) },
	}
	return client.login(ctx, clientID(), prompt)
}

func (c *deviceFlowClient) login(
	parent context.Context,
	clientID string,
	prompt DevicePrompter,
) (*StoredToken, error) {
	if clientID == "" || len(clientID) > 256 {
		return nil, errors.New("invalid GitHub OAuth client ID")
	}
	if prompt == nil {
		return nil, errors.New("device authorization prompt is unavailable")
	}

	device, err := c.requestDeviceCode(parent, clientID)
	if err != nil {
		return nil, err
	}
	if err := prompt(DeviceAuthorization{
		UserCode:        device.UserCode,
		VerificationURI: device.VerificationURI,
	}); err != nil {
		return nil, fmt.Errorf("showing device authorization: %w", err)
	}

	expiresAt := c.clock.Now().Add(time.Duration(device.ExpiresIn) * time.Second)
	ctx, cancel := clock.WithDeadline(parent, c.clock, expiresAt)
	defer cancel()

	interval := time.Duration(device.Interval) * time.Second
	for {
		if err := c.wait(ctx, interval); err != nil {
			if errors.Is(err, context.DeadlineExceeded) && parent.Err() == nil {
				return nil, apperr.New(
					apperr.CodeAuthExpired,
					"device code expired, please try again",
					nil,
				)
			}
			return nil, fmt.Errorf("waiting for device authorization: %w", err)
		}

		if !c.clock.Now().Before(expiresAt) && parent.Err() == nil {
			return nil, apperr.New(apperr.CodeAuthExpired, "device code expired, please try again", nil)
		}

		response, err := c.requestToken(ctx, clientID, device.DeviceCode)
		if err != nil {
			return nil, err
		}
		switch response.Error {
		case "":
			if err := validateToken(*response); err != nil {
				return nil, fmt.Errorf("validating device token: %w", err)
			}
			return storeDeviceToken(ctx, response.AccessToken)
		case "authorization_pending":
			continue
		case "slow_down":
			interval += 5 * time.Second
			if response.Interval > 0 {
				serverInterval := time.Duration(response.Interval) * time.Second
				if serverInterval > interval && serverInterval <= 5*time.Minute {
					interval = serverInterval
				}
			}
		case "expired_token", "token_expired":
			return nil, apperr.New(
				apperr.CodeAuthExpired,
				"device code expired, please try again",
				nil,
			)
		case "access_denied":
			return nil, apperr.New(apperr.CodeAccessDenied, "access denied by user", nil)
		case "device_flow_disabled":
			return nil, errors.New("GitHub Device Flow is not enabled for this OAuth app")
		case "incorrect_client_credentials":
			return nil, errors.New("invalid GitHub OAuth client ID")
		case "incorrect_device_code":
			return nil, errors.New("invalid GitHub device code")
		case "unsupported_grant_type":
			return nil, errors.New("GitHub rejected the Device Flow grant type")
		default:
			return nil, fmt.Errorf(
				"device authorization failed: %q (%q)",
				response.Error,
				response.ErrorDescription,
			)
		}
	}
}

func (c *deviceFlowClient) requestDeviceCode(
	ctx context.Context,
	clientID string,
) (*deviceCodeResponse, error) {
	var response deviceCodeResponse
	if err := c.postForm(ctx, c.deviceCodeURL, url.Values{
		"client_id": {clientID},
		"scope":     {deviceScopes},
	}, &response); err != nil {
		return nil, fmt.Errorf("requesting device code: %w", err)
	}
	if response.DeviceCode == "" || len(response.DeviceCode) > maxDeviceValueSize ||
		response.UserCode == "" || len(response.UserCode) > 64 ||
		response.VerificationURI != githubDeviceURL ||
		response.ExpiresIn <= 0 || response.ExpiresIn > 3600 ||
		response.Interval <= 0 || response.Interval > 300 {
		return nil, errors.New("requesting device code: invalid response")
	}
	return &response, nil
}

func (c *deviceFlowClient) requestToken(
	ctx context.Context,
	clientID, deviceCode string,
) (*deviceTokenResponse, error) {
	var response deviceTokenResponse
	if err := c.postForm(ctx, c.tokenURL, url.Values{
		"client_id":   {clientID},
		"device_code": {deviceCode},
		"grant_type":  {deviceGrantType},
	}, &response); err != nil {
		return nil, fmt.Errorf("polling for device token: %w", err)
	}
	if len(response.Error) > 256 || len(response.ErrorDescription) > maxDeviceValueSize ||
		len(response.ErrorURI) > maxDeviceValueSize {
		return nil, errors.New("polling for device token: invalid response")
	}
	return &response, nil
}

func (c *deviceFlowClient) postForm(
	ctx context.Context,
	endpoint string,
	values url.Values,
	result any,
) error {
	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		endpoint,
		strings.NewReader(values.Encode()),
	)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		_ = resp.Body.Close()
		return fmt.Errorf("unexpected status %d", resp.StatusCode)
	}
	return decodeJSON(resp, result)
}

func storeDeviceToken(ctx context.Context, accessToken string) (*StoredToken, error) {
	login, userID, err := getGitHubUser(ctx, accessToken)
	if err != nil {
		return nil, fmt.Errorf("getting GitHub user: %w", err)
	}
	if login == "" || userID <= 0 {
		return nil, errors.New("getting GitHub user: invalid identity response")
	}

	token := &StoredToken{AccessToken: accessToken, Username: login, UserID: userID}
	if err := SaveToken(token); err != nil {
		return nil, fmt.Errorf("saving token: %w", err)
	}
	return token, nil
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

func validateToken(token deviceTokenResponse) error {
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

// clientID is the GitHub OAuth app to sign in with: ENBU_CLIENT_ID, or enbu's.
func clientID() string {
	if id := os.Getenv("ENBU_CLIENT_ID"); id != "" {
		return id
	}
	return defaultClientID
}
