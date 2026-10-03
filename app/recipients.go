package app

import (
	"context"
	"github.com/enbu-net/enbu/pkg/age"
	"github.com/enbu-net/enbu/pkg/apperr"
	"strings"
)

type RecipientInfo struct {
	Username    string
	Fingerprint string
	PublicKey   string
}

func (a *App) ListRecipients(ctx context.Context) (recipients []RecipientInfo, err error) {
	defer apperr.NormalizeInto(&err)
	store, err := a.workspaceStorage(ctx)
	if err != nil {
		return nil, err
	}
	keys, err := PullAllRecipients(ctx, store)
	if err != nil {
		return nil, err
	}
	for _, key := range keys {
		recipients = append(recipients, RecipientInfo{Username: age.Fingerprint(key), Fingerprint: strings.TrimPrefix(RecipientKey(key), RecipientTagPrefix()), PublicKey: key})
	}
	return recipients, nil
}
