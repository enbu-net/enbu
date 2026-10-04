package secretmap

import (
	"bytes"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"
)

var (
	ErrInvalidDotenv = errors.New("invalid dotenv")
	envNamePattern   = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
)

// ImportDotenv accepts assignments, optional export, comments, and single/double
// quoted values (including multiline values). Double quotes support \\, \" and
// escaped n/r/t/$; unquoted and single-quoted values remain literal.
// It never performs variable expansion, reads the environment, or executes code.
// Duplicate keys are rejected rather than silently overwriting a secret.
func ImportDotenv(data []byte) (SecretMap, error) {
	if len(data) > MaxPayloadBytes || !utf8.Valid(data) || bytes.IndexByte(data, 0) >= 0 {
		return nil, ErrInvalidDotenv
	}
	secrets := SecretMap{}
	rest := strings.TrimPrefix(string(data), "\ufeff")
	for {
		rest = strings.TrimLeft(rest, " \t\r\n")
		if rest == "" {
			break
		}
		if rest[0] == '#' {
			_, rest, _ = strings.Cut(rest, "\n")
			continue
		}
		if strings.HasPrefix(rest, "export ") || strings.HasPrefix(rest, "export\t") {
			rest = strings.TrimLeft(rest[6:], " \t")
		}
		line, _, _ := strings.Cut(rest, "\n")
		equals := strings.IndexByte(line, '=')
		if equals < 0 {
			return nil, fmt.Errorf("%w: expected assignment", ErrInvalidDotenv)
		}
		key := strings.TrimSpace(rest[:equals])
		if len(key) > MaxKeyBytes || !envNamePattern.MatchString(key) {
			return nil, fmt.Errorf("%w: invalid variable name", ErrInvalidDotenv)
		}
		if _, exists := secrets[key]; exists {
			return nil, fmt.Errorf("%w: duplicate variable", ErrInvalidDotenv)
		}
		rest = strings.TrimLeft(rest[equals+1:], " \t")
		var value string
		if rest != "" && (rest[0] == '\'' || rest[0] == '"') {
			var err error
			value, rest, err = parseQuoted(rest)
			if err != nil {
				return nil, err
			}
			// After a closing quote only whitespace or a comment is accepted.
			tail, next, _ := strings.Cut(rest, "\n")
			tail = strings.TrimSpace(tail)
			if tail != "" && tail[0] != '#' {
				return nil, fmt.Errorf("%w: trailing quoted value data", ErrInvalidDotenv)
			}
			rest = next
		} else {
			value, rest, _ = strings.Cut(rest, "\n")
			for i := range len(value) {
				if value[i] == '#' && (i == 0 || value[i-1] == ' ' || value[i-1] == '\t') {
					value = value[:i]
					break
				}
			}
			value = strings.TrimSpace(value)
		}
		secrets[key] = value
		if len(secrets) > MaxEntries {
			return nil, fmt.Errorf("%w: too many entries", ErrInvalidSecretMap)
		}
	}
	if err := secrets.Validate(); err != nil {
		return nil, err
	}
	return secrets, nil
}

func parseQuoted(text string) (string, string, error) {
	quote := text[0]
	var value strings.Builder
	for i := 1; i < len(text); i++ {
		b := text[i]
		if b == quote {
			return value.String(), text[i+1:], nil
		}
		if quote == '"' && b == '\\' {
			i++
			if i == len(text) {
				break
			}
			switch text[i] {
			case 'n':
				b = '\n'
			case 'r':
				b = '\r'
			case 't':
				b = '\t'
			case '\\', '"', '$':
				b = text[i]
			default:
				return "", "", fmt.Errorf("%w: unsupported escape", ErrInvalidDotenv)
			}
		}
		value.WriteByte(b)
	}
	return "", "", fmt.Errorf("%w: unterminated quoted value", ErrInvalidDotenv)
}

// ExportDotenv returns sorted assignments. Env-name and NUL constraints are
// exporter-specific; SecretMap itself has no environment-variable semantics.
func ExportDotenv(secrets SecretMap) ([]byte, error) {
	if err := secrets.Validate(); err != nil {
		return nil, err
	}
	keys := make([]string, 0, len(secrets))
	for key, value := range secrets {
		if !envNamePattern.MatchString(key) || strings.ContainsRune(value, 0) {
			return nil, ErrInvalidDotenv
		}
		keys = append(keys, key)
	}
	sort.Strings(keys)
	escape := strings.NewReplacer("\\", "\\\\", "\"", "\\\"", "\n", "\\n", "\r", "\\r", "\t", "\\t", "$", "\\$")
	var result strings.Builder
	for _, key := range keys {
		fmt.Fprintf(&result, "%s=\"%s\"\n", key, escape.Replace(secrets[key]))
		if result.Len() > MaxPayloadBytes {
			return nil, fmt.Errorf("%w: output too large", ErrInvalidDotenv)
		}
	}
	return []byte(result.String()), nil
}
