package bundle

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"unicode"
)

func Marshal(secrets map[string]string) []byte {
	data, _ := json.Marshal(secrets)
	return data
}

func Unmarshal(data []byte) (map[string]string, error) {
	var secrets map[string]string
	if err := json.Unmarshal(data, &secrets); err != nil {
		return nil, fmt.Errorf("parsing bundle: %w", err)
	}
	return secrets, nil
}

func ToDotEnv(secrets map[string]string) ([]byte, error) {
	keys := make([]string, 0, len(secrets))
	for k := range secrets {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var sb strings.Builder
	for _, k := range keys {
		if err := validateDotEnvString("key", k); err != nil {
			return nil, err
		}
		val := secrets[k]
		if err := validateDotEnvString("value", val); err != nil {
			return nil, fmt.Errorf("key %q: %w", k, err)
		}
		val = strings.ReplaceAll(val, "\\", "\\\\")
		val = strings.ReplaceAll(val, "\"", "\\\"")
		fmt.Fprintf(&sb, "%s=\"%s\"\n", k, val)
	}
	return []byte(sb.String()), nil
}

func validateDotEnvString(field, s string) error {
	for _, r := range s {
		if r == '\n' || r == '\r' || (unicode.IsControl(r) && r != '\t') {
			return fmt.Errorf(".env %s contains invalid control character %q", field, r)
		}
	}
	return nil
}
