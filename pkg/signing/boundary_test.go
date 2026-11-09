package signing

import (
	"crypto/elliptic"
	"math/big"
	"strings"
	"testing"
)

// Boundaries that mutation testing showed no test pinned down.

func TestDeviceIDValidateRejectsEachDefectAlone(t *testing.T) {
	good := PublicKey{Alg: Ed25519, Bytes: make([]byte, 32)}.DeviceID()
	if err := good.Validate(); err != nil {
		t.Fatalf("a derived ID is invalid: %v", err)
	}
	for name, id := range map[string]DeviceID{
		"not hex":    DeviceID(strings.Repeat("g", 64)),
		"too short":  good[:62],
		"too long":   good + "00",
		"upper case": DeviceID(strings.ToUpper(string(good))),
		"empty":      "",
	} {
		if id.Validate() == nil {
			t.Errorf("%s ID %q was accepted", name, id)
		}
	}
}

func TestValidateDomainRejectsTheSeparatorAnywhere(t *testing.T) {
	for _, d := range []string{"\x00", "\x00enbu", "enbu\x00", "en\x00bu", ""} {
		if ValidateDomain(d) == nil {
			t.Errorf("domain %q was accepted", d)
		}
	}
	if ValidateDomain(DomainState) != nil {
		t.Fatal("a real domain was refused")
	}
}

// P256Signature keeps s at exactly half the group order (it is low already)
// and folds anything above it; folding the half itself would produce a
// high-S signature that Verify refuses.
func TestP256SignatureFoldsOnlyAboveHalfTheOrder(t *testing.T) {
	n := elliptic.P256().Params().N
	half := halfOrder()
	r := big.NewInt(7)
	for _, c := range []struct {
		s, want *big.Int
	}{
		{half, half},
		{new(big.Int).Sub(half, big.NewInt(1)), new(big.Int).Sub(half, big.NewInt(1))},
		{new(big.Int).Add(half, big.NewInt(1)), new(big.Int).Sub(n, new(big.Int).Add(half, big.NewInt(1)))},
	} {
		sig, err := P256Signature(r, c.s)
		if err != nil {
			t.Fatal(err)
		}
		if got := new(big.Int).SetBytes(sig[32:]); got.Cmp(c.want) != 0 {
			t.Errorf("s=%v became %v, want %v", c.s, got, c.want)
		}
		if new(big.Int).SetBytes(sig[32:]).Cmp(half) > 0 {
			t.Errorf("s=%v produced a high-S signature", c.s)
		}
	}
	for _, bad := range []*big.Int{big.NewInt(0), n, new(big.Int).Neg(big.NewInt(1))} {
		if _, err := P256Signature(r, bad); err == nil {
			t.Errorf("s=%v was accepted", bad)
		}
		if _, err := P256Signature(bad, big.NewInt(1)); err == nil {
			t.Errorf("r=%v was accepted", bad)
		}
	}
}
