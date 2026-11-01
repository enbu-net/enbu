package cli

import (
	"bytes"
	"io"
	"os"
	"slices"
	"strings"
	"sync"

	"golang.org/x/term"
)

// concealed replaces a secret value in the command's output.
const concealed = "<concealed by enbu>"

// minMaskedLength is the shortest value that is masked. Shorter values, such
// as "true" or a port number, appear in ordinary output too often for masking
// to do anything but garble it.
const minMaskedLength = 6

// maskedValues are the secret values to conceal, longest first, so a value
// that contains another is replaced whole. Each line of a multi-line value,
// such as a PEM key, is a value too, since commands often print it line by
// line or with other line endings.
func maskedValues(secrets map[string]string) [][]byte {
	var values [][]byte
	add := func(v string) {
		if len(v) >= minMaskedLength && !slices.ContainsFunc(values, func(b []byte) bool { return string(b) == v }) {
			values = append(values, []byte(v))
		}
	}
	for _, v := range secrets {
		add(v)
		if strings.ContainsAny(v, "\r\n") {
			for _, line := range strings.FieldsFunc(v, func(r rune) bool { return r == '\r' || r == '\n' }) {
				add(line)
			}
		}
	}
	slices.SortFunc(values, func(a, b []byte) int { return len(b) - len(a) })
	return values
}

// outputFor is where the command's output goes: w itself, or a masker over w
// when masking applies. Masking applies unless disabled and w is not a
// terminal: a log or a CI job keeps what it receives, while on a terminal the
// command must keep its terminal (colors, progress, prompts), which a filter
// in between would take away.
func outputFor(w io.Writer, values [][]byte, disabled bool) io.Writer {
	if disabled || len(values) == 0 || isTerminal(w) {
		return w
	}
	return &masker{w: w, values: values}
}

func isTerminal(w io.Writer) bool {
	f, ok := w.(*os.File)
	return ok && term.IsTerminal(int(f.Fd()))
}

// masker writes through to w with every secret value replaced by concealed.
// It holds back only a trailing part that could begin a value, so output
// reaches w as it is written; Flush writes what is held back at the end.
type masker struct {
	mu      sync.Mutex
	w       io.Writer
	values  [][]byte
	pending []byte
}

func (m *masker) Write(p []byte) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.pending = append(m.pending, p...)
	out, held := m.conceal(m.pending, false)
	m.pending = append(m.pending[:0], held...)
	if _, err := m.w.Write(out); err != nil {
		return 0, err
	}
	return len(p), nil
}

// Flush writes what is held back, concealing the values in it: no more output
// can complete a longer value.
func (m *masker) Flush() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.pending) == 0 {
		return nil
	}
	out, _ := m.conceal(m.pending, true)
	m.pending = m.pending[:0]
	_, err := m.w.Write(out)
	return err
}

// conceal returns b with the values replaced, and the end of b that must wait
// for more output because it may begin a value. With final, nothing waits.
func (m *masker) conceal(b []byte, final bool) (out, held []byte) {
	rest := b
	for {
		i, n := m.firstMatch(rest)
		if i < 0 {
			break
		}
		// A longer value may start here and still be arriving; wait for it.
		if !final && m.beginsLonger(rest[i:], n) {
			return append(out, rest[:i]...), rest[i:]
		}
		out = append(out, rest[:i]...)
		out = append(out, concealed...)
		rest = rest[i+n:]
	}
	if final {
		return append(out, rest...), nil
	}
	hold := m.prefixLen(rest)
	return append(out, rest[:len(rest)-hold]...), rest[len(rest)-hold:]
}

// firstMatch is the position and length of the earliest value in b, the
// longest one where several start at the same place, or -1.
func (m *masker) firstMatch(b []byte) (int, int) {
	at, n := -1, 0
	for _, v := range m.values {
		if i := bytes.Index(b, v); i >= 0 && (at < 0 || i < at) {
			at, n = i, len(v)
		}
	}
	return at, n
}

// beginsLonger reports whether b, which starts with a value of length n, is
// also the incomplete start of a longer value.
func (m *masker) beginsLonger(b []byte, n int) bool {
	for _, v := range m.values {
		if len(v) > n && len(b) < len(v) && bytes.HasPrefix(v, b) {
			return true
		}
	}
	return false
}

// prefixLen is the length of the longest end of b that begins some value.
// For each value it tries only the starts that match the value's first byte,
// earliest (longest) first, so a long value such as a PEM key stays cheap.
func (m *masker) prefixLen(b []byte) int {
	longest := 0
	for _, v := range m.values {
		for j := max(0, len(b)-len(v)+1); j < len(b)-longest; j++ {
			if b[j] == v[0] && bytes.HasPrefix(v, b[j:]) {
				longest = len(b) - j
				break
			}
		}
	}
	return longest
}
