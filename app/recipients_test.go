package app

import (
	"context"
	"testing"
)

func TestListRecipientsComesFromControl(t *testing.T) {
	kp := mustKeyPair(t)
	a := newTestApp(t, "owner", "repo", "default", kp, nil)
	recipients, err := a.ListRecipients(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(recipients) != 1 || recipients[0].PublicKey != kp.PublicKey {
		t.Fatalf("recipients=%v", recipients)
	}
}
