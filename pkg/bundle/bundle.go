package bundle

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
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
		if strings.ContainsAny(k, "\n\r") {
			return nil, fmt.Errorf(".env key contains newline character")
		}
		val := secrets[k]
		val = strings.ReplaceAll(val, "\\", "\\\\")
		val = strings.ReplaceAll(val, "\"", "\\\"")
		val = strings.ReplaceAll(val, "\n", "\\n")
		val = strings.ReplaceAll(val, "\r", "\\r")
		fmt.Fprintf(&sb, "%s=\"%s\"\n", k, val)
	}
	return []byte(sb.String()), nil
}
