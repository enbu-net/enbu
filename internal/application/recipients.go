package app

import (
	"context"
	"strings"

	"github.com/enbu-net/enbu/pkg/apperr"
	"golang.org/x/sync/errgroup"
)

type RecipientInfo struct {
	Username    string
	Fingerprint string
	PublicKey   string
}

func (a *App) ListRecipients(ctx context.Context) (recipients []RecipientInfo, err error) {
	defer apperr.NormalizeInto(&err)

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
				return nil
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
	_ = group.Wait()

	results := make([]RecipientInfo, 0, len(pulled))
	for _, result := range pulled {
		if result.ok {
			results = append(results, result.recipient)
		}
	}
	return results, nil
}
