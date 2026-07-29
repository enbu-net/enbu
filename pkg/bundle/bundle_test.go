package bundle_test

import (
	"testing"

	"github.com/enbu-net/enbu/pkg/bundle"
)

func TestMarshalUnmarshal(t *testing.T) {
	secrets := map[string]string{
		"DB_URL":  "postgres://localhost/dev",
		"API_KEY": "sk-1234",
	}

	data := bundle.Marshal(secrets)
	got, err := bundle.Unmarshal(data)
	if err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	if got["DB_URL"] != secrets["DB_URL"] || got["API_KEY"] != secrets["API_KEY"] {
		t.Fatalf("round-trip mismatch: got %v", got)
	}
}

func TestToDotEnv(t *testing.T) {
	secrets := map[string]string{
		"B_KEY": "val2",
		"A_KEY": "val1",
	}

	result := string(bundle.ToDotEnv(secrets))
	expected := "A_KEY=\"val1\"\nB_KEY=\"val2\"\n"

	if result != expected {
		t.Fatalf("got %q, want %q", result, expected)
	}
}

func TestToDotEnvEscaping(t *testing.T) {
	secrets := map[string]string{
		"QUOTED": `he said "hello"`,
		"SLASH":  `path\to\file`,
	}

	result := string(bundle.ToDotEnv(secrets))
	expected := "QUOTED=\"he said \\\"hello\\\"\"\nSLASH=\"path\\\\to\\\\file\"\n"

	if result != expected {
		t.Fatalf("got %q, want %q", result, expected)
	}
}

func TestToDotEnvEmpty(t *testing.T) {
	secrets := map[string]string{}
	result := bundle.ToDotEnv(secrets)
	if len(result) != 0 {
		t.Fatalf("expected empty, got %q", result)
	}
}

func TestToDotEnvMultibyte(t *testing.T) {
	secrets := map[string]string{
		"MSG": "こんにちは世界",
	}

	result := string(bundle.ToDotEnv(secrets))
	expected := "MSG=\"こんにちは世界\"\n"

	if result != expected {
		t.Fatalf("got %q, want %q", result, expected)
	}
}

func TestUnmarshalInvalid(t *testing.T) {
	_, err := bundle.Unmarshal([]byte("not json"))
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestToDotEnvEmptyValue(t *testing.T) {
	secrets := map[string]string{
		"EMPTY": "",
	}

	result := string(bundle.ToDotEnv(secrets))
	expected := "EMPTY=\"\"\n"

	if result != expected {
		t.Fatalf("got %q, want %q", result, expected)
	}
}
