package auth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/enbu-net/enbu/pkg/apperr"
)

const (
	githubDeviceCodeURL = "https://github.com/login/device/code"
	githubTokenURL      = "https://github.com/login/oauth/access_token"
	githubDeviceURL     = "https://github.com/login/device"
	deviceGrantType     = "urn:ietf:params:oauth:grant-type:device_code"
	deviceScopes        = "repo read:org write:packages"
	maxDeviceValueSize  = 2048
)

type DeviceAuthorization struct {
	UserCode        string
	VerificationURI string
}

type DevicePrompter func(DeviceAuthorization) error

type deviceFlowClient struct {
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

func LoginDevice(ctx context.Context, clientID string, prompt DevicePrompter) (*StoredToken, error) {
	client := &deviceFlowClient{
		deviceCodeURL: githubDeviceCodeURL,
		tokenURL:      githubTokenURL,
		http:          newHTTPClient(),
		wait:          waitForDevicePoll,
	}
	return client.login(ctx, clientID, prompt)
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

	ctx, cancel := context.WithTimeout(parent, time.Duration(device.ExpiresIn)*time.Second)
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

		response, err := c.requestToken(ctx, clientID, device.DeviceCode)
		if err != nil {
			return nil, err
		}
		switch response.Error {
		case "":
			token := exchangeResponse{
				AccessToken: response.AccessToken,
				TokenType:   response.TokenType,
				Scope:       response.Scope,
			}
			if err := validateToken(token); err != nil {
				return nil, fmt.Errorf("validating device token: %w", err)
			}
			return storeDeviceToken(ctx, token.AccessToken)
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

func waitForDevicePoll(ctx context.Context, duration time.Duration) error {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
