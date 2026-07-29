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

	result, err := bundle.ToDotEnv(secrets)
	if err != nil {
		t.Fatalf("ToDotEnv: %v", err)
	}
	expected := "A_KEY=\"val1\"\nB_KEY=\"val2\"\n"
	if string(result) != expected {
		t.Fatalf("got %q, want %q", result, expected)
	}
}

func TestToDotEnvEscaping(t *testing.T) {
	secrets := map[string]string{
		"QUOTED": `he said "hello"`,
		"SLASH":  `path\to\file`,
	}

	result, err := bundle.ToDotEnv(secrets)
	if err != nil {
		t.Fatalf("ToDotEnv: %v", err)
	}
	expected := "QUOTED=\"he said \\\"hello\\\"\"\nSLASH=\"path\\\\to\\\\file\"\n"
	if string(result) != expected {
		t.Fatalf("got %q, want %q", result, expected)
	}
}

func TestToDotEnvEmpty(t *testing.T) {
	result, err := bundle.ToDotEnv(map[string]string{})
	if err != nil {
		t.Fatalf("ToDotEnv: %v", err)
	}
	if len(result) != 0 {
		t.Fatalf("expected empty, got %q", result)
	}
}

func TestToDotEnvMultibyte(t *testing.T) {
	secrets := map[string]string{
		"MSG": "こんにちは世界",
	}

	result, err := bundle.ToDotEnv(secrets)
	if err != nil {
		t.Fatalf("ToDotEnv: %v", err)
	}
	expected := "MSG=\"こんにちは世界\"\n"
	if string(result) != expected {
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
	result, err := bundle.ToDotEnv(map[string]string{"EMPTY": ""})
	if err != nil {
		t.Fatalf("ToDotEnv: %v", err)
	}
	expected := "EMPTY=\"\"\n"
	if string(result) != expected {
		t.Fatalf("got %q, want %q", result, expected)
	}
}

func TestToDotEnvNewlineInValue(t *testing.T) {
	_, err := bundle.ToDotEnv(map[string]string{"KEY": "line1\nline2"})
	if err == nil {
		t.Fatal("expected error for newline in value")
	}
}

func TestToDotEnvNewlineInKey(t *testing.T) {
	_, err := bundle.ToDotEnv(map[string]string{"KEY\nINJECT": "val"})
	if err == nil {
		t.Fatal("expected error for newline in key")
	}
}
