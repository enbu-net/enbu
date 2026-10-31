package desktop

import (
	"testing"

	"github.com/enbu-net/enbu/pkg/apperr"
)

func TestImportSecretsFromDotenvContent(t *testing.T) {
	f := newMembersFixture(t)
	result, err := f.alice.ImportSecrets("", "A=1\nB=2\n", false)
	if err != nil || len(result.Added) != 2 || result.Environment != "default" {
		t.Fatalf("import: %+v %v", result, err)
	}
	// Another value stops the import unless overwrite is set, as with --overwrite.
	if _, err := f.alice.ImportSecrets("", "A=changed\nB=2\n", false); !apperr.Is(err, apperr.CodeSecretExists) {
		t.Fatalf("changed value without overwrite: %v", err)
	}
	result, err = f.alice.ImportSecrets("", "A=changed\nB=2\n", true)
	if err != nil || len(result.Updated) != 1 || len(result.Unchanged) != 1 {
		t.Fatalf("overwrite: %+v %v", result, err)
	}
	if _, err := f.alice.ImportSecrets("", "not dotenv", false); !apperr.Is(err, apperr.CodeInvalidArgument) {
		t.Fatalf("invalid content: %v", err)
	}
}

func TestSetAdminGrantsAndRevokes(t *testing.T) {
	f := newMembersFixture(t)
	if err := f.alice.ApproveMember(f.bobDevice); err != nil {
		t.Fatal(err)
	}
	if err := f.alice.SetAdmin(f.bobDevice, true); err != nil {
		t.Fatal(err)
	}
	if !isAdmin(t, f.alice, f.bobDevice) {
		t.Fatal("bob is not an admin after the grant")
	}
	if err := f.bob.SetAdmin(f.bobDevice, false); err != nil {
		t.Fatal(err)
	}
	if isAdmin(t, f.alice, f.bobDevice) {
		t.Fatal("bob is still an admin after the revoke")
	}
	if err := f.bob.SetAdmin(f.bobDevice, true); !apperr.Is(err, apperr.CodeAccessDenied) {
		t.Fatalf("a member made itself an admin: %v", err)
	}
}

func isAdmin(t *testing.T, s *Service, device string) bool {
	t.Helper()
	members, err := s.ListMembers()
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range members {
		if m.DeviceID == device {
			return m.Admin
		}
	}
	t.Fatalf("%s is not a member", device)
	return false
}

func TestResolveMemberForkRefusesAnUnforkedWorkspace(t *testing.T) {
	f := newMembersFixture(t)
	if err := f.alice.ResolveMemberFork(); !apperr.Is(err, apperr.CodeInvalidArgument) {
		t.Fatalf("resolve without a fork: %v", err)
	}
}

func TestGetIdentityDescribesThisDevice(t *testing.T) {
	f := newMembersFixture(t)
	info, err := f.alice.GetIdentity()
	if err != nil || info.Recipient == "" || info.Fingerprint == "" {
		t.Fatalf("identity: %+v %v", info, err)
	}
	members, err := f.alice.ListMembers()
	if err != nil || len(members) != 1 || members[0].Fingerprint != info.Fingerprint || !members[0].Self {
		t.Fatalf("members: %+v %v", members, err)
	}
}
