package dotenv

import (
	"bytes"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestParse(t *testing.T) {
	t.Parallel()
	input := []byte("\ufeff# comment\r\nexport A = unquoted # note\r\nB='  literal $A # \\n  '\nC=\"quote\\\" slash\\\\ newline\\n cr\\r tab\\t dollar\\$\" # note\nD=abc#def\nEMPTY=\nMULTI='first\nsecond'\n")
	want := map[string]string{"A": "unquoted", "B": "  literal $A # \\n  ", "C": "quote\" slash\\ newline\n cr\r tab\t dollar$", "D": "abc#def", "EMPTY": "", "MULTI": "first\nsecond"}
	got, err := Parse(input)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Parse = %#v, want %#v", got, want)
	}
	for _, empty := range [][]byte{nil, []byte("# only a comment\n \t\r\n")} {
		got, err := Parse(empty)
		if err != nil || got == nil || len(got) != 0 {
			t.Fatalf("empty parse = %#v, %v", got, err)
		}
	}
}

func TestFormat(t *testing.T) {
	t.Parallel()
	got, err := Format(map[string]string{"B_KEY": "val2", "A_KEY": `he said "hi" \ $HOME`, "MSG": "こんにちは"})
	if err != nil {
		t.Fatal(err)
	}
	want := "A_KEY=\"he said \\\"hi\\\" \\\\ \\$HOME\"\nB_KEY=\"val2\"\nMSG=\"こんにちは\"\n"
	if string(got) != want {
		t.Fatalf("Format = %q, want %q", got, want)
	}
	if empty, err := Format(nil); err != nil || len(empty) != 0 {
		t.Fatalf("empty Format = %q, %v", empty, err)
	}
	if _, err := Format(map[string]string{"A\nB": "x"}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("newline key error = %v", err)
	}
}

func TestRoundTripPreservesValues(t *testing.T) {
	t.Parallel()
	want := map[string]string{"EMPTY": "", "UNICODE": "e\u0301 日本語", "QUOTES": "'\"\\", "LINES": "\r\n\t", "LITERAL": "${HOME} $(touch /tmp/never) `never` # text", "SPACES": "  abc  "}
	encoded, err := Format(want)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Parse(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("round trip = %#v, want %#v", got, want)
	}
	if !bytes.HasPrefix(encoded, []byte("EMPTY=\"\"\n")) {
		t.Fatal("keys are not sorted")
	}
}

func TestParseRejectsInvalidInput(t *testing.T) {
	t.Parallel()
	for name, data := range map[string][]byte{
		"missing equals": []byte("A"),
		"empty key":      []byte("=value"),
		"invalid name":   []byte("A-B=value"),
		"numeric name":   []byte("1A=value"),
		"duplicate":      []byte("A=x\nA=y"),
		"unterminated":   []byte("A='value"),
		"trailing data":  []byte("A='value' garbage"),
		"bad escape":     []byte("A=\"\\q\""),
		"NUL":            []byte("A=a\x00b"),
		"UTF8":           {'A', '=', 0xff},
		"oversized":      bytes.Repeat([]byte{'x'}, MaxBytes+1),
		"long key":       []byte(strings.Repeat("A", MaxKeyBytes+1) + "=value"),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse(data); !errors.Is(err, ErrInvalid) {
				t.Fatalf("Parse error = %v", err)
			}
		})
	}
	var many strings.Builder
	for i := range MaxEntries + 1 {
		fmt.Fprintf(&many, "K%d=value\n", i)
	}
	if _, err := Parse([]byte(many.String())); !errors.Is(err, ErrInvalid) {
		t.Fatalf("entry limit: %v", err)
	}
}

func FuzzRoundTrip(f *testing.F) {
	f.Add([]byte("A=\"quoted\\nvalue\"\n"))
	f.Add([]byte("A=${HOME}\n"))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		secrets, err := Parse(data)
		if err != nil {
			return
		}
		formatted, err := Format(secrets)
		if err != nil {
			t.Fatal(err)
		}
		got, err := Parse(formatted)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(got, secrets) {
			t.Fatal("round trip changed values")
		}
	})
}
