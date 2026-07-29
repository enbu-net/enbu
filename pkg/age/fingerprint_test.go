package age

import "testing"

func TestFingerprint(t *testing.T) {
	fp := Fingerprint("age1abc123")
	if len(fp) != 8 {
		t.Errorf("fingerprint length = %d, want 8", len(fp))
	}

	fp2 := Fingerprint("age1abc123")
	if fp != fp2 {
		t.Error("fingerprint not deterministic")
	}

	fp3 := Fingerprint("age1different")
	if fp == fp3 {
		t.Error("different keys produced same fingerprint")
	}
}
