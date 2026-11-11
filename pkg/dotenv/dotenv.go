// Package dotenv parses and renders .env files.
package dotenv

import (
	"bytes"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"
)

const (
	MaxBytes    = 16 * 1024 * 1024
	MaxEntries  = 4096
	MaxKeyBytes = 1024
)

var (
	ErrInvalid  = errors.New("invalid dotenv")
	namePattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
	escaper     = strings.NewReplacer("\\", "\\\\", "\"", "\\\"", "\n", "\\n", "\r", "\\r", "\t", "\\t", "$", "\\$")
)

// Parse accepts assignments, optional export, comments, and single/double
// quoted values (including multiline values). Double quotes support \\, \" and
// escaped n/r/t/$; unquoted and single-quoted values remain literal.
// It never performs variable expansion, reads the environment, or executes code.
// Duplicate keys are rejected rather than silently overwriting a secret.
func Parse(data []byte) (map[string]string, error) {
	if len(data) > MaxBytes || !utf8.Valid(data) || bytes.IndexByte(data, 0) >= 0 {
		return nil, ErrInvalid
	}
	secrets := map[string]string{}
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
			return nil, fmt.Errorf("%w: expected assignment", ErrInvalid)
		}
		key := strings.TrimSpace(rest[:equals])
		if len(key) > MaxKeyBytes || !namePattern.MatchString(key) {
			return nil, fmt.Errorf("%w: invalid variable name", ErrInvalid)
		}
		if _, exists := secrets[key]; exists {
			return nil, fmt.Errorf("%w: duplicate variable", ErrInvalid)
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
				return nil, fmt.Errorf("%w: trailing quoted value data", ErrInvalid)
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
			return nil, fmt.Errorf("%w: too many entries", ErrInvalid)
		}
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
				return "", "", fmt.Errorf("%w: unsupported escape", ErrInvalid)
			}
		}
		value.WriteByte(b)
	}
	return "", "", fmt.Errorf("%w: unterminated quoted value", ErrInvalid)
}

// Format renders sorted, double-quoted assignments that Parse reads back. It
// refuses secrets Parse would reject, so a written file can always be read again.
func Format(secrets map[string]string) ([]byte, error) {
	if len(secrets) > MaxEntries {
		return nil, fmt.Errorf("%w: too many entries", ErrInvalid)
	}
	keys := make([]string, 0, len(secrets))
	for key, value := range secrets {
		if len(key) > MaxKeyBytes || !namePattern.MatchString(key) {
			return nil, fmt.Errorf("%w: invalid variable name", ErrInvalid)
		}
		if !utf8.ValidString(value) || strings.IndexByte(value, 0) >= 0 {
			return nil, fmt.Errorf("%w: invalid value", ErrInvalid)
		}
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var result strings.Builder
	for _, key := range keys {
		fmt.Fprintf(&result, "%s=\"%s\"\n", key, escaper.Replace(secrets[key]))
		if result.Len() > MaxBytes {
			return nil, fmt.Errorf("%w: output too large", ErrInvalid)
		}
	}
	return []byte(result.String()), nil
}
