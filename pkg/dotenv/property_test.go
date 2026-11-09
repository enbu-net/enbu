package dotenv

import (
	"reflect"
	"strings"
	"testing"
	"unicode/utf8"

	"pgregory.net/rapid"
)

// INPUT-3: whatever enbu writes as .env reads back as the same secrets, with
// no expansion, and whatever Format refuses is something Parse could not
// read back.

// tricky characters for a .env value: quotes, escapes, expansion, comments,
// line breaks, separators and non-ASCII text.
var trickyRunes = []rune{'"', '\'', '\\', '$', '{', '}', '#', '=', ' ', '\t', '\n', '\r', 'a', 'Z', '0', 'é', '秘', '🔑', '`', ';'}

func genValue(t *rapid.T, label string) string {
	return string(rapid.SliceOfN(rapid.SampledFrom(trickyRunes), 0, 24).Draw(t, label))
}

func TestDotenvRoundTripsGeneratedEnvironments(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		secrets := map[string]string{}
		n := rapid.IntRange(0, 8).Draw(t, "entries")
		for range n {
			key := rapid.StringMatching(`[A-Za-z_][A-Za-z0-9_]{0,12}`).Draw(t, "key")
			secrets[key] = genValue(t, "value")
		}
		formatted, err := Format(secrets)
		if err != nil {
			t.Fatalf("Format refused valid secrets %q: %v", secrets, err)
		}
		again, err := Format(secrets)
		if err != nil || string(again) != string(formatted) {
			t.Fatal("Format is not deterministic")
		}
		got, err := Parse(formatted)
		if err != nil {
			t.Fatalf("Parse cannot read what Format wrote:\n%s\n%v", formatted, err)
		}
		if !reflect.DeepEqual(got, secrets) && !(len(got) == 0 && len(secrets) == 0) {
			t.Fatalf("round trip changed the secrets:\n%q\n%q", secrets, got)
		}
	})
}

func TestDotenvFormatRefusesWhatCannotRoundTrip(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		key := rapid.String().Draw(t, "key")
		value := rapid.String().Draw(t, "value")
		if rapid.Bool().Draw(t, "invalid utf8") {
			value += "\xff"
		}
		if rapid.Bool().Draw(t, "nul") {
			value += "\x00"
		}
		formatted, err := Format(map[string]string{key: value})
		valid := namePattern.MatchString(key) && len(key) <= MaxKeyBytes && utf8.ValidString(value) && !strings.Contains(value, "\x00")
		if valid != (err == nil) {
			t.Fatalf("key %q value %q: valid %v, Format error %v", key, value, valid, err)
		}
		if err == nil {
			got, err := Parse(formatted)
			if err != nil || got[key] != value || len(got) != 1 {
				t.Fatalf("key %q value %q did not round-trip: %q %v", key, value, got, err)
			}
		}
	})
}
