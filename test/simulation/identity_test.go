package simulation

import "testing"

func TestSyntheticIdentityCreationContract(t *testing.T) {
	keys := &Keys{Tape: NewTape(5, "")}
	first, info, _, err := keys.Create("workspace")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = first.Close() }()
	if !info.Created || info.Algorithm != "X25519" {
		t.Fatalf("new identity metadata: %+v", info)
	}
	again, reused, _, err := keys.Create("workspace")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = again.Close() }()
	if reused.Created || reused.Recipient != info.Recipient {
		t.Fatalf("reused identity metadata: %+v", reused)
	}
	signer, created, _, err := keys.CreateSigner("workspace")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = signer.Close() }()
	if !created.Created {
		t.Fatal("new signer not marked created")
	}
	same, reusedSigner, _, err := keys.CreateSigner("workspace")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = same.Close() }()
	if reusedSigner.Created || reusedSigner.DeviceID != created.DeviceID {
		t.Fatal("signer creation is not idempotent")
	}
	pending, pendingInfo, _, err := keys.CreatePending("workspace")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = pending.Close() }()
	if !pendingInfo.Created || pendingInfo.Algorithm != "ML-KEM-768 + X25519" {
		t.Fatalf("pending metadata: %+v", pendingInfo)
	}
	if err := keys.PromotePending("workspace"); err != nil {
		t.Fatal(err)
	}
	current, err := keys.Info("workspace")
	if err != nil {
		t.Fatal(err)
	}
	if current.Created || current.Recipient != pendingInfo.Recipient {
		t.Fatal("pending identity not promoted")
	}
	retained, err := keys.LoadRetained("workspace")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		for _, id := range retained {
			_ = id.Close()
		}
	}()
	if len(retained) != 1 || retained[0].Recipient().String() != info.Recipient {
		t.Fatal("old identity not retained")
	}
}

func TestSyntheticIdentitiesAreScopedPerWorkspace(t *testing.T) {
	keys := &Keys{Tape: NewTape(5, "")}
	a, _, _, err := keys.Create("a")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = a.Close() }()
	b, _, _, err := keys.Create("b")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = b.Close() }()
	if a.Recipient().String() == b.Recipient().String() {
		t.Fatal("encryption identity reused across workspaces")
	}
	sa, _, _, err := keys.CreateSigner("a")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sa.Close() }()
	sb, _, _, err := keys.CreateSigner("b")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sb.Close() }()
	if sa.Public().DeviceID() == sb.Public().DeviceID() {
		t.Fatal("signing identity reused across workspaces")
	}
}
