package cli

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

func maskAll(t *testing.T, secrets map[string]string, chunks ...string) string {
	t.Helper()
	var out bytes.Buffer
	m := &masker{w: &out, values: maskedValues(secrets)}
	for _, c := range chunks {
		if n, err := m.Write([]byte(c)); err != nil || n != len(c) {
			t.Fatalf("Write(%q) = %d, %v", c, n, err)
		}
	}
	if err := m.Flush(); err != nil {
		t.Fatal(err)
	}
	return out.String()
}

func TestMaskerConcealsValues(t *testing.T) {
	secrets := map[string]string{"TOKEN": "s3cr3t-token", "SHORT": "abc", "PREFIX": "s3cr3t"}
	tests := []struct {
		name   string
		chunks []string
		want   string
	}{
		{"whole", []string{"token=s3cr3t-token\n"}, "token=<concealed by enbu>\n"},
		// The longer value wins where both start, so nothing of it is left.
		{"longest first", []string{"a s3cr3t b s3cr3t-token c"}, "a <concealed by enbu> b <concealed by enbu> c"},
		{"split across writes", []string{"x s3cr", "3t-to", "ken y"}, "x <concealed by enbu> y"},
		{"one byte at a time", strings.Split("[s3cr3t-token]", ""), "[<concealed by enbu>]"},
		{"too short to mask", []string{"abc"}, "abc"},
		// A held-back start of a value that never completes is written at the end.
		{"unfinished prefix", []string{"ends with s3cr"}, "ends with s3cr"},
		{"no secrets", []string{"plain output"}, "plain output"},
		// The shorter value at the end is concealed even though it was held
		// back in case the longer one followed.
		{"shorter value at the end", []string{"end s3cr3t-to"}, "end <concealed by enbu>-to"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := maskAll(t, secrets, tt.chunks...); got != tt.want {
				t.Fatalf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestMaskerWritesThroughWithoutWaiting(t *testing.T) {
	var out bytes.Buffer
	m := &masker{w: &out, values: maskedValues(map[string]string{"K": "s3cr3t-token"})}
	_, _ = m.Write([]byte("progress 10%\r"))
	if out.String() != "progress 10%\r" {
		t.Fatalf("output %q was held back", out.String())
	}
}

func TestMaskedValuesSplitsLines(t *testing.T) {
	pem := "-----BEGIN KEY-----\nMIIBVgIBADANBgkq\r\n-----END KEY-----"
	got := maskAll(t, map[string]string{"PEM": pem}, "key line: MIIBVgIBADANBgkq\n")
	if got != "key line: <concealed by enbu>\n" {
		t.Fatalf("got %q", got)
	}
}

func TestOutputFor(t *testing.T) {
	values := maskedValues(map[string]string{"K": "s3cr3t-token"})
	var buf bytes.Buffer
	if _, ok := outputFor(&buf, values, false).(*masker); !ok {
		t.Fatal("a buffer is not a terminal and must be masked")
	}
	if outputFor(&buf, values, true) != &buf {
		t.Fatal("--no-masking must pass the writer through")
	}
	if outputFor(&buf, nil, false) != &buf {
		t.Fatal("nothing to mask must pass the writer through")
	}
	f, err := os.CreateTemp(t.TempDir(), "out")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	if _, ok := outputFor(f, values, false).(*masker); !ok {
		t.Fatal("a file is not a terminal and must be masked")
	}
}

func TestSameWriter(t *testing.T) {
	var a, b bytes.Buffer
	if !sameWriter(&a, &a) || sameWriter(&a, &b) {
		t.Fatal("pointer comparison")
	}
	if sameWriter(sliceWriter{}, sliceWriter{}) {
		t.Fatal("values of a type that cannot be compared are never the same")
	}
}

// sliceWriter is a writer whose type cannot be compared with ==.
type sliceWriter []byte

func (sliceWriter) Write(p []byte) (int, error) { return len(p), nil }
