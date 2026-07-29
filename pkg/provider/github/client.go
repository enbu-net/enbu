package github

import (
	"context"
	"fmt"
	"net/http"

	"github.com/enbu-net/enbu/pkg/provider"
	githubsdk "github.com/google/go-github/v89/github"
)

type Client struct {
	sdk     *githubsdk.Client
	initErr error
}

func NewClient(token string) *Client {
	return NewClientWithHTTPClient(token, http.DefaultClient)
}

func NewClientWithHTTPClient(token string, httpClient *http.Client) *Client {
	return newClient(token, httpClient, "")
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

func (c *Client) IsOrganization(ctx context.Context, login string) bool {
	if c.initErr != nil {
		return false
	}
	user, _, err := c.sdk.Users.Get(ctx, login)
	return err == nil && user.GetType() == "Organization"
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

func (c *Client) SourceRepoURL(owner, repo string) string {
	return fmt.Sprintf("https://github.com/%s/%s", owner, repo)
}

type CreateRepoResult struct {
	Owner    string
	Name     string
	SSHURL   string
	HTTPSURL string
}

type RepositoryOwner struct {
	Login        string `json:"login"`
	Organization bool   `json:"organization"`
}

func (c *Client) ListRepositoryOwners(ctx context.Context) ([]RepositoryOwner, error) {
	user, err := c.GetUser(ctx)
	if err != nil {
		return nil, err
	}

	owners := []RepositoryOwner{{Login: user.Login}}
	options := &githubsdk.ListOptions{PerPage: 100}
	for {
		organizations, response, err := c.sdk.Organizations.List(ctx, "", options)
		if err != nil {
			return nil, err
		}
		for _, organization := range organizations {
			owners = append(owners, RepositoryOwner{
				Login:        organization.GetLogin(),
				Organization: true,
			})
		}
		if response.NextPage == 0 {
			break
		}
		options.Page = response.NextPage
	}
	return owners, nil
}

func (c *Client) CreateRepository(
	ctx context.Context,
	organization string,
	name string,
	private bool,
) (*CreateRepoResult, error) {
	if c.initErr != nil {
		return nil, c.initErr
	}
	repository, _, err := c.sdk.Repositories.Create(ctx, organization, &githubsdk.Repository{
		Name:    githubsdk.Ptr(name),
		Private: githubsdk.Ptr(private),
	})
	if err != nil {
		return nil, err
	}
	return &CreateRepoResult{
		Owner:    repository.GetOwner().GetLogin(),
		Name:     repository.GetName(),
		SSHURL:   repository.GetSSHURL(),
		HTTPSURL: repository.GetCloneURL(),
	}, nil
}
