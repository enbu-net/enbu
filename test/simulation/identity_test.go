package simulation

import "testing"

func TestSyntheticIdentityCreationContract(t *testing.T) {
	t.Parallel()
	keys := &Keys{Tape: NewTape(5, "")}
	first, info, _, err := keys.Create("workspace")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = first.Close() }()
	if !info.Created || info.Algorithm != "MLKEM768-X25519" || info.DeviceID == "" {
		t.Fatalf("new identity metadata: %+v", info)
	}
	again, reused, _, err := keys.Create("workspace")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = again.Close() }()
	if reused.Created || reused.Recipient != info.Recipient || reused.DeviceID != info.DeviceID {
		t.Fatalf("reused identity metadata: %+v", reused)
	}
}

func TestSyntheticIdentitiesAreScopedPerWorkspace(t *testing.T) {
	t.Parallel()
	keys := &Keys{Tape: NewTape(5, "")}
	_, a, _, err := keys.Create("a")
	if err != nil {
		t.Fatal(err)
	}
	_, b, _, err := keys.Create("b")
	if err != nil {
		t.Fatal(err)
	}
	if a.Recipient == b.Recipient || a.DeviceID == b.DeviceID {
		t.Fatal("keys reused across workspaces")
	}
}
