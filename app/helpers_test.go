package app

import (
	"context"
	"fmt"
	"testing"

	"github.com/enbu-net/enbu/utils/oci"
)

func TestIsNotFoundError(t *testing.T) {
	if !IsNotFoundError(fmt.Errorf("wrapped: %w", oci.ErrNotFound)) {
		t.Fatal("typed not-found error was not recognized")
	}
	for _, message := range []string{
		"response status code 404",
		"NAME_UNKNOWN: repository name not known to registry",
		"MANIFEST_UNKNOWN: manifest unknown",
		"failed to perform FetchReference: not found",
	} {
		if IsNotFoundError(fmt.Errorf("%s", message)) {
			t.Errorf("IsNotFoundError(%q) = true, want false for untyped text", message)
		}
	}
	for _, message := range []string{"unauthorized", "denied", "connection reset"} {
		if IsNotFoundError(fmt.Errorf("%s", message)) {
			t.Errorf("IsNotFoundError(%q) = true, want false", message)
		}
	}
}

func TestPullAllRecipients_MissingPackageIsEmpty(t *testing.T) {
	reg := &listTagsErrorRegistry{
		memRegistry: newMemRegistry(),
		err:         fmt.Errorf("listing: %w", oci.ErrNotFound),
	}

	recipients, err := PullAllRecipients(context.Background(), reg, "ghcr.io/owner/repo-enbu", "token")
	if err != nil {
		t.Fatalf("PullAllRecipients: %v", err)
	}
	if len(recipients) != 0 {
		t.Fatalf("recipients = %v, want empty", recipients)
	}
}

func TestPullAllRecipients_RegistryFailureIsNotHidden(t *testing.T) {
	reg := &listTagsErrorRegistry{
		memRegistry: newMemRegistry(),
		err:         fmt.Errorf("unauthorized"),
	}

	if _, err := PullAllRecipients(context.Background(), reg, "ghcr.io/owner/repo-enbu", "token"); err == nil {
		t.Fatal("expected registry error")
	}
}

func TestPullAllRecipients_SkipsRecipientRemovedAfterListing(t *testing.T) {
	base := newMemRegistry()
	ref := "ghcr.io/owner/repo-enbu"
	if err := base.Push(context.Background(), ref+":recipient-alice-aabbccdd", "", nil, "", nil); err != nil {
		t.Fatal(err)
	}
	reg := &pullErrorRegistry{
		memRegistry: base,
		err:         fmt.Errorf("pulling recipient: %w", oci.ErrNotFound),
	}

	recipients, err := PullAllRecipients(context.Background(), reg, ref, "token")
	if err != nil {
		t.Fatalf("PullAllRecipients: %v", err)
	}
	if len(recipients) != 0 {
		t.Fatalf("recipients = %v, want empty", recipients)
	}
}
