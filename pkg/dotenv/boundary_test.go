package dotenv

import (
	"fmt"
	"strings"
	"testing"
)

// Limits and the comment rule, at their exact boundaries.

func TestParseLimitsAtTheBoundary(t *testing.T) {
	key := strings.Repeat("K", MaxKeyBytes)
	if _, err := Parse([]byte(key + "=v\n")); err != nil {
		t.Fatalf("a key of exactly %d bytes was refused: %v", MaxKeyBytes, err)
	}
	if _, err := Parse([]byte(key + "K=v\n")); err == nil {
		t.Fatalf("a key of %d bytes was accepted", MaxKeyBytes+1)
	}

	var b strings.Builder
	for i := range MaxEntries {
		fmt.Fprintf(&b, "K%d=v\n", i)
	}
	if got, err := Parse([]byte(b.String())); err != nil || len(got) != MaxEntries {
		t.Fatalf("exactly %d entries: %d, %v", MaxEntries, len(got), err)
	}
	if _, err := Parse([]byte(b.String() + "EXTRA=v\n")); err == nil {
		t.Fatalf("%d entries were accepted", MaxEntries+1)
	}

	line := "A=" + strings.Repeat("v", MaxBytes-3) + "\n"
	if len(line) != MaxBytes {
		t.Fatal("test input has the wrong size")
	}
	if _, err := Parse([]byte(line)); err != nil {
		t.Fatalf("a file of exactly %d bytes was refused: %v", MaxBytes, err)
	}
	if _, err := Parse([]byte(line + " ")); err == nil {
		t.Fatalf("a file of %d bytes was accepted", MaxBytes+1)
	}

	for _, bad := range []string{"\x00A=v\n", "A=v\x00\n", "A=\xff\n"} {
		if _, err := Parse([]byte(bad)); err == nil {
			t.Errorf("%q was accepted", bad)
		}
	}
}

func TestInlineCommentsNeedWhitespaceBeforeTheHash(t *testing.T) {
	for in, want := range map[string]string{
		"A=x #c\n":   "x",
		"A=x\t#c\n":  "x",
		"A=x#c\n":    "x#c",
		"A=x# c\n":   "x# c",
		"A=#c\n":     "",
		"A=a#b #c\n": "a#b",
	} {
		got, err := Parse([]byte(in))
		if err != nil || got["A"] != want {
			t.Errorf("%q: got %q (%v), want %q", in, got["A"], err, want)
		}
	}
}

func TestFormatLimitsAtTheBoundary(t *testing.T) {
	key := strings.Repeat("K", MaxKeyBytes)
	if _, err := Format(map[string]string{key: "v"}); err != nil {
		t.Fatalf("a key of exactly %d bytes was refused: %v", MaxKeyBytes, err)
	}
	if _, err := Format(map[string]string{key + "K": "v"}); err == nil {
		t.Fatalf("a key of %d bytes was accepted", MaxKeyBytes+1)
	}
	many := map[string]string{}
	for i := range MaxEntries {
		many[fmt.Sprintf("K%d", i)] = "v"
	}
	if _, err := Format(many); err != nil {
		t.Fatalf("exactly %d entries were refused: %v", MaxEntries, err)
	}
	many["EXTRA"] = "v"
	if _, err := Format(many); err == nil {
		t.Fatalf("%d entries were accepted", MaxEntries+1)
	}
	if _, err := Format(map[string]string{"A": "\x00v"}); err == nil {
		t.Fatal("a value starting with NUL was accepted")
	}
	// A=" + value + "\n" is exactly MaxBytes.
	exact := strings.Repeat("v", MaxBytes-5)
	if out, err := Format(map[string]string{"A": exact}); err != nil || len(out) != MaxBytes {
		t.Fatalf("output of exactly %d bytes: %d, %v", MaxBytes, len(out), err)
	}
	if _, err := Format(map[string]string{"A": exact + "v"}); err == nil {
		t.Fatalf("output of %d bytes was accepted", MaxBytes+1)
	}
}
