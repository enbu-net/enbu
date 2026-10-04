package secretmap

import (
	"bytes"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestImportDotenv(t *testing.T) {
	t.Parallel()
	input := []byte("\ufeff# comment\r\nexport A = unquoted # note\r\nB='  literal $A # \\n  '\nC=\"quote\\\" slash\\\\ newline\\n cr\\r tab\\t dollar\\$\" # note\nD=abc#def\nEMPTY=\nMULTI='first\nsecond'\n")
	want := SecretMap{"A": "unquoted", "B": "  literal $A # \\n  ", "C": "quote\" slash\\ newline\n cr\r tab\t dollar$", "D": "abc#def", "EMPTY": "", "MULTI": "first\nsecond"}
	got, err := ImportDotenv(input)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Import = %#v, want %#v", got, want)
	}
	for _, empty := range [][]byte{nil, []byte("# only a comment\n \t\r\n")} {
		got, err := ImportDotenv(empty)
		if err != nil || got == nil || len(got) != 0 {
			t.Fatalf("empty import = %#v, %v", got, err)
		}
	}
}

func TestDotenvRoundTripPreservesValues(t *testing.T) {
	t.Parallel()
	want := SecretMap{"EMPTY": "", "UNICODE": "e\u0301 日本語", "QUOTES": "'\"\\", "LINES": "\r\n\t", "LITERAL": "${HOME} $(touch /tmp/never) `never` # text", "SPACES": "  abc  "}
	encoded, err := ExportDotenv(want)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ImportDotenv(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("round trip = %#v, want %#v", got, want)
	}
	if !bytes.HasPrefix(encoded, []byte("EMPTY=\"\"\n")) {
		t.Fatal("export keys are not sorted")
	}
	if !strings.Contains(string(encoded), "\\${HOME}") {
		t.Fatal("export did not escape variable expansion")
	}
}

func TestDotenvRejectsInvalidInput(t *testing.T) {
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
		"oversized":      bytes.Repeat([]byte{'x'}, MaxPayloadBytes+1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ImportDotenv(data); !errors.Is(err, ErrInvalidDotenv) {
				t.Fatalf("import error = %v", err)
			}
		})
	}
	for name, secrets := range map[string]SecretMap{
		"semantic name": {"service/path": "value"},
		"NUL value":     {"A": "x\x00y"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ExportDotenv(secrets); !errors.Is(err, ErrInvalidDotenv) {
				t.Fatalf("export error = %v", err)
			}
		})
	}
}

func TestDotenvBounds(t *testing.T) {
	t.Parallel()
	var input strings.Builder
	for i := range MaxEntries + 1 {
		fmt.Fprintf(&input, "K%d=value\n", i)
	}
	if _, err := ImportDotenv([]byte(input.String())); !errors.Is(err, ErrInvalidSecretMap) {
		t.Fatalf("entry limit: %v", err)
	}
	if _, err := ImportDotenv([]byte(strings.Repeat("A", MaxKeyBytes+1) + "=value")); !errors.Is(err, ErrInvalidDotenv) {
		t.Fatalf("key limit: %v", err)
	}
	if _, err := ExportDotenv(SecretMap{"A": strings.Repeat("\n", MaxPayloadBytes/2)}); !errors.Is(err, ErrInvalidDotenv) {
		t.Fatalf("escaped output limit: %v", err)
	}
}

func FuzzDotenvRoundTrip(f *testing.F) {
	f.Add([]byte("A=\"quoted\\nvalue\"\n"))
	f.Add([]byte("A=${HOME}\n"))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		secrets, err := ImportDotenv(data)
		if err != nil {
			return
		}
		exported, err := ExportDotenv(secrets)
		if err != nil {
			return
		} // serialized form can exceed the bound after escaping
		got, err := ImportDotenv(exported)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(got, secrets) {
			t.Fatal("dotenv semantic round trip changed values")
		}
	})
}
