package app

import (
	"context"
	"fmt"
	"strings"

	"golang.org/x/sync/errgroup"
)

type RecipientInfo struct {
	Username    string
	Fingerprint string
	PublicKey   string
}

func (a *App) ListRecipients(ctx context.Context) ([]RecipientInfo, error) {
	accessToken, _, err := a.TokenProvider.LoadToken()
	if err != nil {
		return nil, err
	}
	owner, repo, err := a.RepoDetector.LoadRepo()
	if err != nil {
		return nil, err
	}

	ref := a.registryRef(owner, repo)
	tags, err := a.Registry.ListTags(ctx, ref, accessToken)
	if err != nil {
		if IsNotFoundError(err) {
			return []RecipientInfo{}, nil
		}
		return nil, err
	}

	var recipientTags []string
	for _, tag := range tags {
		if IsUserRecipientTag(tag) {
			recipientTags = append(recipientTags, tag)
		}
	}

	type pullResult struct {
		recipient RecipientInfo
		ok        bool
	}
	pulled := make([]pullResult, len(recipientTags))
	var group errgroup.Group
	group.SetLimit(8)
	for i, tag := range recipientTags {
		i, tag := i, tag
		group.Go(func() error {
			tagRef := ref + ":" + tag
			data, err := a.Registry.Pull(ctx, tagRef, accessToken)
			if err != nil {
				if IsNotFoundError(err) {
					return nil
				}
				return fmt.Errorf("pulling recipient %s: %w", tag, err)
			}
			// tag format: recipient-{username}-{fingerprint}
			without := strings.TrimPrefix(tag, RecipientTagPrefix())
			lastDash := strings.LastIndex(without, "-")
			if lastDash < 0 {
				return nil
			}
			pulled[i] = pullResult{ok: true, recipient: RecipientInfo{
				Username:    without[:lastDash],
				Fingerprint: without[lastDash+1:],
				PublicKey:   strings.TrimSpace(string(data)),
			}}
			return nil
		})
	}
	if err := group.Wait(); err != nil {
		return nil, err
	}

	results := make([]RecipientInfo, 0, len(pulled))
	for _, result := range pulled {
		if result.ok {
			results = append(results, result.recipient)
		}
	}
	return results, nil
}
