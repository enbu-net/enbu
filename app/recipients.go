package app

import (
	"context"

	"github.com/enbu-net/enbu/pkg/apperr"
)

type RecipientInfo struct {
	Username    string
	Fingerprint string
	PublicKey   string
}

// ListRecipients returns the encryption recipients of the verified Control.
// Objects in storage never contribute to this list.
func (a *App) ListRecipients(ctx context.Context) (recipients []RecipientInfo, err error) {
	defer apperr.NormalizeInto(&err)
	s, err := a.openControl(ctx)
	if err != nil {
		return nil, err
	}
	for _, p := range s.head.Principals {
		recipients = append(recipients, RecipientInfo{Username: p.ID.Fingerprint(), Fingerprint: p.ID.Fingerprint(), PublicKey: p.Recipient})
	}
	return recipients, nil
}
