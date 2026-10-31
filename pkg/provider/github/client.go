package github

import (
	"context"
	"net/http"

	"github.com/enbu-net/enbu/pkg/provider"
	githubsdk "github.com/google/go-github/v93/github"
)

type Client struct {
	sdk     *githubsdk.Client
	initErr error
}

// apiBaseURL is overridden with -ldflags only by local E2E builds.
var apiBaseURL string

func NewClient(token string) *Client {
	return newClient(token, http.DefaultClient, apiBaseURL)
}

func NewClientWithHTTPClient(token string, httpClient *http.Client) *Client {
	return newClient(token, httpClient, apiBaseURL)
}

func newClient(token string, httpClient *http.Client, baseURL string) *Client {
	options := []githubsdk.ClientOptionsFunc{
		githubsdk.WithHTTPClient(httpClient),
		githubsdk.WithAuthToken(token),
	}
	if baseURL != "" {
		options = append(options, githubsdk.WithURLs(&baseURL, &baseURL))
	}
	sdk, err := githubsdk.NewClient(options...)
	return &Client{sdk: sdk, initErr: err}
}

func (c *Client) GetUser(ctx context.Context) (*provider.User, error) {
	if c.initErr != nil {
		return nil, c.initErr
	}
	user, _, err := c.sdk.Users.Get(ctx, "")
	if err != nil {
		return nil, err
	}
	return &provider.User{ID: user.GetID(), Login: user.GetLogin(), Type: user.GetType()}, nil
}
