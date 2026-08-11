// Package schema contains semantic codecs for the built-in Resource schemas.
// The codecs never decide access or materialize a path; they only validate and
// canonicalize an already selected stream.
package schema

import (
	"bufio"
	"bytes"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"sort"
	"strings"
	"unicode/utf8"
)

const (
	SchemaSecretMap  = "schemas.enbu.net/v1alpha1/SecretMap"
	SchemaOpaque     = "schemas.enbu.net/v1alpha1/Opaque"
	SchemaFileTree   = "schemas.enbu.net/v1alpha1/FileTree"
	SchemaValueTree  = "schemas.enbu.net/v1alpha1/ValueTree"
	SchemaTable      = "schemas.enbu.net/v1alpha1/Table"
	SchemaFindingSet = "schemas.enbu.net/v1alpha1/FindingSet"
	SchemaRegoPolicy = "schemas.enbu.net/v1alpha1/RegoPolicy"
	MaxOpaqueBytes   = 256 * 1024 * 1024
	MaxTableCells    = 1_000_000
)

var (
	ErrInvalidSchema = errors.New("schema: invalid built-in value")
	ErrInvalidPath   = errors.New("schema: invalid file-tree path")
)

type SecretMap map[string]string

func (values SecretMap) Validate() error {
	if len(values) > 100_000 {
		return fmt.Errorf("%w: too many secret keys", ErrInvalidSchema)
	}
	for key, value := range values {
		if err := validateKey(key); err != nil {
			return fmt.Errorf("%w: key %q: %v", ErrInvalidSchema, key, err)
		}
		if !utf8.ValidString(value) || strings.IndexByte(value, 0) >= 0 {
			return fmt.Errorf("%w: key %q has invalid UTF-8/NUL", ErrInvalidSchema, key)
		}
	}
	return nil
}

func EncodeSecretMap(values SecretMap) ([]byte, error) {
	if err := values.Validate(); err != nil {
		return nil, err
	}
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var output bytes.Buffer
	for _, key := range keys {
		encoded, _ := json.Marshal(values[key])
		output.WriteString(key)
		output.WriteByte('=')
		output.Write(encoded)
		output.WriteByte('\n')
	}
	return output.Bytes(), nil
}

func DecodeSecretMap(data []byte) (SecretMap, error) {
	if len(data) > MaxOpaqueBytes {
		return nil, fmt.Errorf("%w: secret map too large", ErrInvalidSchema)
	}
	values := SecretMap{}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "export ") {
			line = strings.TrimSpace(strings.TrimPrefix(line, "export "))
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			return nil, fmt.Errorf("%w: malformed assignment", ErrInvalidSchema)
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if err := validateKey(key); err != nil {
			return nil, fmt.Errorf("%w: key %q: %v", ErrInvalidSchema, key, err)
		}
		if _, exists := values[key]; exists {
			return nil, fmt.Errorf("%w: duplicate key %q", ErrInvalidSchema, key)
		}
		if len(value) >= 2 && ((value[0] == '"' && value[len(value)-1] == '"') || (value[0] == '\'' && value[len(value)-1] == '\'')) {
			if value[0] == '"' {
				var decoded string
				if err := json.Unmarshal([]byte(value), &decoded); err != nil {
					return nil, fmt.Errorf("%w: quoted value %q", ErrInvalidSchema, key)
				}
				value = decoded
			} else {
				value = value[1 : len(value)-1]
			}
		}
		values[key] = value
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return values, values.Validate()
}

func ValidateOpaque(data []byte) error {
	if len(data) > MaxOpaqueBytes || !utf8.Valid(data) {
		// Opaque binary resources are allowed; only the size bound applies.
		if len(data) > MaxOpaqueBytes {
			return fmt.Errorf("%w: opaque payload too large", ErrInvalidSchema)
		}
	}
	return nil
}

func ValidateRegoPolicy(source []byte) error {
	if len(source) == 0 || len(source) > 256*1024 || !utf8.Valid(source) || bytes.IndexByte(source, 0) >= 0 {
		return fmt.Errorf("%w: Rego source bounds", ErrInvalidSchema)
	}
	return nil
}

func ValidateFileTreePath(value string) error {
	if value == "" || strings.HasPrefix(value, "/") || strings.HasPrefix(value, "\\") || strings.Contains(value, "\\") || strings.Contains(value, ":") || strings.ContainsRune(value, 0) {
		return ErrInvalidPath
	}
	if path.Clean(value) != value {
		return ErrInvalidPath
	}
	parts := strings.Split(value, "/")
	for _, part := range parts {
		if part == "" || part == "." || part == ".." || strings.HasSuffix(part, ".") || strings.HasSuffix(part, " ") || isWindowsReserved(part) || strings.ContainsAny(part, "<>|?*") {
			return ErrInvalidPath
		}
	}
	return nil
}

func ValidateFileTreePaths(paths []string) error {
	seen := make(map[string]struct{}, len(paths))
	for _, value := range paths {
		if err := ValidateFileTreePath(value); err != nil {
			return err
		}
		folded := strings.ToLower(value)
		if _, exists := seen[folded]; exists {
			return fmt.Errorf("%w: case-fold collision", ErrInvalidPath)
		}
		seen[folded] = struct{}{}
	}
	return nil
}

type Table struct {
	Rows [][]string `json:"rows"`
}

func DecodeTable(r io.Reader) (Table, error) {
	reader := csv.NewReader(io.LimitReader(r, MaxOpaqueBytes))
	reader.FieldsPerRecord = -1
	var table Table
	cells := 0
	for {
		row, err := reader.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return Table{}, fmt.Errorf("%w: CSV: %v", ErrInvalidSchema, err)
		}
		cells += len(row)
		if cells > MaxTableCells {
			return Table{}, fmt.Errorf("%w: table too large", ErrInvalidSchema)
		}
		table.Rows = append(table.Rows, row)
	}
	return table, nil
}

func EncodeTable(table Table) ([]byte, error) {
	cells := 0
	var output bytes.Buffer
	writer := csv.NewWriter(&output)
	for _, row := range table.Rows {
		cells += len(row)
		if cells > MaxTableCells {
			return nil, fmt.Errorf("%w: table too large", ErrInvalidSchema)
		}
		if err := writer.Write(row); err != nil {
			return nil, fmt.Errorf("%w: CSV: %v", ErrInvalidSchema, err)
		}
	}
	writer.Flush()
	if err := writer.Error(); err != nil {
		return nil, err
	}
	return output.Bytes(), nil
}

type Finding struct {
	Rule     string `json:"rule"`
	Severity string `json:"severity"`
	Message  string `json:"message,omitempty"`
}
type FindingSet struct {
	Findings []Finding `json:"findings"`
}

func (set FindingSet) Validate() error {
	if len(set.Findings) > 100_000 {
		return fmt.Errorf("%w: finding count", ErrInvalidSchema)
	}
	for _, finding := range set.Findings {
		if err := validateKey(finding.Rule); err != nil {
			return fmt.Errorf("%w: finding fields", ErrInvalidSchema)
		}
		if err := validateKey(finding.Severity); err != nil || !utf8.ValidString(finding.Message) {
			return fmt.Errorf("%w: finding fields", ErrInvalidSchema)
		}
	}
	return nil
}

func EncodeFindingSet(set FindingSet) ([]byte, error) {
	if err := set.Validate(); err != nil {
		return nil, err
	}
	return json.Marshal(set)
}

func DecodeFindingSet(data []byte) (FindingSet, error) {
	var set FindingSet
	if err := json.Unmarshal(data, &set); err != nil {
		return FindingSet{}, fmt.Errorf("%w: finding JSON", ErrInvalidSchema)
	}
	return set, set.Validate()
}

func ValidateValueTree(data []byte) error {
	if len(data) == 0 || len(data) > MaxOpaqueBytes {
		return fmt.Errorf("%w: value tree size", ErrInvalidSchema)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return fmt.Errorf("%w: value tree JSON", ErrInvalidSchema)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return fmt.Errorf("%w: trailing value tree", ErrInvalidSchema)
	}
	return nil
}

func validateKey(key string) error {
	if key == "" || len(key) > 253 || strings.ContainsAny(key, " \t\r\n") || strings.ContainsRune(key, 0) || !utf8.ValidString(key) {
		return errors.New("invalid key")
	}
	for _, character := range key {
		if character < 0x20 || character == 0x7f || character == '=' {
			return errors.New("invalid key")
		}
	}
	return nil
}

func isWindowsReserved(name string) bool {
	base := strings.ToUpper(strings.TrimSuffix(name, "."))
	if index := strings.IndexByte(base, '.'); index >= 0 {
		base = base[:index]
	}
	switch base {
	case "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9":
		return true
	default:
		return false
	}
}
