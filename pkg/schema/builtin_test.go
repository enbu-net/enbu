package schema

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestSecretMapDotEnvRoundTripIncludingEmbeddedWiFiCredentials(t *testing.T) {
	input := []byte("# device configuration\nexport WIFI_SSID=lab-network\nWIFI_PASSWORD=\"correct horse\"\n")
	values, err := DecodeSecretMap(input)
	if err != nil {
		t.Fatal(err)
	}
	if values["WIFI_SSID"] != "lab-network" || values["WIFI_PASSWORD"] != "correct horse" {
		t.Fatalf("values = %#v", values)
	}
	encoded, err := EncodeSecretMap(values)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(encoded, []byte("WIFI_PASSWORD=\"correct horse\"\nWIFI_SSID=\"lab-network\"\n")) {
		t.Fatalf("canonical dotenv = %q", encoded)
	}
}

func TestSecretMapRejectsDuplicateAndMalformedInput(t *testing.T) {
	for _, input := range []string{"A=1\nA=2\n", "not-an-assignment\n", "A=\x00\n"} {
		if _, err := DecodeSecretMap([]byte(input)); !errors.Is(err, ErrInvalidSchema) {
			t.Fatalf("DecodeSecretMap(%q) = %v", input, err)
		}
	}
}

func TestOpaqueAcceptsBinaryAndBoundsIt(t *testing.T) {
	if err := ValidateOpaque([]byte{0, 1, 2, 255}); err != nil {
		t.Fatal(err)
	}
	if err := ValidateOpaque(make([]byte, MaxOpaqueBytes+1)); !errors.Is(err, ErrInvalidSchema) {
		t.Fatalf("oversized opaque error = %v", err)
	}
}

func TestFileTreePathValidationIsPortableAndCaseCollisionAware(t *testing.T) {
	if err := ValidateFileTreePaths([]string{"etc/config", "README"}); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/etc/passwd", "../secret", "a\\b", "CON", "a/../b", "a/"} {
		if err := ValidateFileTreePath(path); !errors.Is(err, ErrInvalidPath) {
			t.Fatalf("path %q error = %v", path, err)
		}
	}
	if err := ValidateFileTreePaths([]string{"Readme", "README"}); !errors.Is(err, ErrInvalidPath) {
		t.Fatalf("case collision error = %v", err)
	}
}

func TestTableAndFindingSetBounds(t *testing.T) {
	table, err := DecodeTable(strings.NewReader("name,value\nssid,lab\n"))
	if err != nil || len(table.Rows) != 2 {
		t.Fatalf("table = %#v, %v", table, err)
	}
	encoded, err := EncodeTable(table)
	if err != nil || !bytes.Contains(encoded, []byte("ssid,lab")) {
		t.Fatalf("encoded table = %q, %v", encoded, err)
	}
	set := FindingSet{Findings: []Finding{{Rule: "wifi.password", Severity: "high", Message: "embedded credential"}}}
	findingBytes, err := EncodeFindingSet(set)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeFindingSet(findingBytes); err != nil {
		t.Fatal(err)
	}
}

func TestValueTreeRejectsTrailingJSON(t *testing.T) {
	if err := ValidateValueTree([]byte(`{"a":1}`)); err != nil {
		t.Fatal(err)
	}
	if err := ValidateValueTree([]byte(`{"a":1} {"b":2}`)); !errors.Is(err, ErrInvalidSchema) {
		t.Fatalf("trailing JSON error = %v", err)
	}
}
