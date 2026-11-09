// Package tla runs TLC on the refinement models in spec/conformance and reads the states it
// dumps, so Go tests can check the implementation against what a model
// decided (model conformance).
package tla

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// Value is a TLA+ value as TLC prints it: int64, string, bool, Set, Seq or
// Record.
type Value any

// Set is a TLA+ set, in the order TLC printed it.
type Set []Value

// Seq is a TLA+ sequence or tuple.
type Seq []Value

// Record is a TLA+ record (or a function whose domain is strings).
type Record map[string]Value

// State maps each variable of a model to its value.
type State map[string]Value

// Parse reads one value in TLC's output syntax.
func Parse(s string) (Value, error) {
	p := &parser{s: s}
	v, err := p.value()
	if err != nil {
		return nil, err
	}
	p.space()
	if p.i != len(p.s) {
		return nil, fmt.Errorf("trailing input at %d: %q", p.i, p.rest())
	}
	return v, nil
}

type parser struct {
	s string
	i int
}

func (p *parser) rest() string {
	r := p.s[p.i:]
	if len(r) > 30 {
		r = r[:30]
	}
	return r
}

func (p *parser) space() {
	for p.i < len(p.s) && strings.ContainsRune(" \t\r\n", rune(p.s[p.i])) {
		p.i++
	}
}

func (p *parser) eat(tok string) bool {
	p.space()
	if strings.HasPrefix(p.s[p.i:], tok) {
		p.i += len(tok)
		return true
	}
	return false
}

func (p *parser) value() (Value, error) {
	p.space()
	switch {
	case p.eat("{"):
		items, err := p.items("}")
		return Set(items), err
	case p.eat("<<"):
		items, err := p.items(">>")
		return Seq(items), err
	case p.eat("["):
		return p.record()
	case p.eat("TRUE"):
		return true, nil
	case p.eat("FALSE"):
		return false, nil
	case p.i < len(p.s) && p.s[p.i] == '"':
		return p.str()
	case p.i < len(p.s) && (p.s[p.i] == '-' || (p.s[p.i] >= '0' && p.s[p.i] <= '9')):
		j := p.i + 1
		for j < len(p.s) && p.s[j] >= '0' && p.s[j] <= '9' {
			j++
		}
		n, err := strconv.ParseInt(p.s[p.i:j], 10, 64)
		p.i = j
		return n, err
	}
	return nil, fmt.Errorf("unexpected input at %d: %q", p.i, p.rest())
}

func (p *parser) items(end string) ([]Value, error) {
	var out []Value
	if p.eat(end) {
		return out, nil
	}
	for {
		v, err := p.value()
		if err != nil {
			return nil, err
		}
		out = append(out, v)
		if p.eat(end) {
			return out, nil
		}
		if !p.eat(",") {
			return nil, fmt.Errorf("expected , or %s at %d: %q", end, p.i, p.rest())
		}
	}
}

func (p *parser) record() (Value, error) {
	r := Record{}
	if p.eat("]") {
		return r, nil
	}
	for {
		p.space()
		j := p.i
		for j < len(p.s) && (p.s[j] == '_' || p.s[j] >= 'a' && p.s[j] <= 'z' || p.s[j] >= 'A' && p.s[j] <= 'Z' || p.s[j] >= '0' && p.s[j] <= '9') {
			j++
		}
		if j == p.i {
			return nil, fmt.Errorf("expected a field name at %d: %q", p.i, p.rest())
		}
		name := p.s[p.i:j]
		p.i = j
		if !p.eat("|->") {
			return nil, fmt.Errorf("expected |-> at %d: %q", p.i, p.rest())
		}
		v, err := p.value()
		if err != nil {
			return nil, err
		}
		r[name] = v
		if p.eat("]") {
			return r, nil
		}
		if !p.eat(",") {
			return nil, fmt.Errorf("expected , or ] at %d: %q", p.i, p.rest())
		}
	}
}

func (p *parser) str() (Value, error) {
	var b strings.Builder
	p.i++ // opening quote
	for p.i < len(p.s) {
		c := p.s[p.i]
		switch {
		case c == '"':
			p.i++
			return b.String(), nil
		case c == '\\' && p.i+1 < len(p.s):
			c = p.s[p.i+1]
			switch c {
			case 'n':
				c = '\n'
			case 't':
				c = '\t'
			case 'f':
				c = '\f'
			case 'r':
				c = '\r'
			}
			b.WriteByte(c)
			p.i += 2
		default:
			b.WriteByte(c)
			p.i++
		}
	}
	return nil, errors.New("unterminated string")
}

// ParseDump reads the states TLC writes with -dump (no dot format).
func ParseDump(text string) ([]State, error) {
	var states []State
	var cur State
	var name string
	var val strings.Builder
	flush := func() error {
		if name == "" {
			return nil
		}
		v, err := Parse(val.String())
		if err != nil {
			return fmt.Errorf("variable %s: %w", name, err)
		}
		cur[name] = v
		name = ""
		val.Reset()
		return nil
	}
	for _, line := range strings.Split(text, "\n") {
		trimmed := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(trimmed, "State ") && strings.HasSuffix(trimmed, ":"):
			if err := flush(); err != nil {
				return nil, err
			}
			cur = State{}
			states = append(states, cur)
		case strings.HasPrefix(trimmed, "/\\ ") && cur != nil:
			if err := flush(); err != nil {
				return nil, err
			}
			n, v, ok := strings.Cut(strings.TrimPrefix(trimmed, "/\\ "), " = ")
			if !ok {
				return nil, fmt.Errorf("bad line %q", line)
			}
			name = n
			val.WriteString(v)
		case cur != nil && name != "":
			val.WriteString(" ")
			val.WriteString(trimmed)
		}
	}
	if err := flush(); err != nil {
		return nil, err
	}
	return states, nil
}

// SpecDir is spec/conformance of this repository, found from the calling test's
// working directory.
func SpecDir(t testing.TB) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "spec", "conformance", "checks.toml")); err == nil {
			return filepath.Join(dir, "spec", "conformance")
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("spec/conformance not found above the test directory")
		}
		dir = parent
	}
}

// Executable finds TLC for a model conformance test. These tests take
// minutes, so they run only with ENBU_REQUIRE_TLC=1 (CI's formal job and
// task formal/conformance), and there a missing TLC is a failure.
func Executable(t testing.TB) string {
	t.Helper()
	if os.Getenv("ENBU_REQUIRE_TLC") != "1" {
		t.Skip("model conformance runs with ENBU_REQUIRE_TLC=1 (task formal/conformance)")
	}
	if path := os.Getenv("ENBU_TLC"); path != "" {
		if strings.ContainsAny(path, `/\`) {
			abs, err := filepath.Abs(path)
			if err != nil {
				t.Fatal(err)
			}
			return abs
		}
		return path
	}
	if path, err := exec.LookPath("tlc"); err == nil {
		// tlc -h exits with 1; an aqua proxy without the package prints no usage.
		if out, _ := exec.Command(path, "-h").CombinedOutput(); bytes.Contains(out, []byte("-simulate")) {
			return path
		}
	}
	t.Fatal("TLC is required (ENBU_REQUIRE_TLC=1) but not found; install it with aqua (yashikota/tlc-static)")
	return ""
}

// Dump runs TLC on module with cfg (the contents of a .cfg file) in a scratch
// copy of spec/tla and returns every distinct reachable state.
func Dump(t testing.TB, module, cfg string) []State {
	t.Helper()
	var states []State
	DumpEach(t, module, cfg, func(s State) { states = append(states, s) })
	return states
}

// Heap is the Java heap TLC may use; its fingerprint set and queue spill to
// disk beyond it.
func Heap() string {
	if h := os.Getenv("ENBU_TLC_HEAP"); h != "" {
		return h
	}
	return "2g"
}

// DumpEach is Dump for large state spaces: it hands each state to fn as it
// reads the dump instead of keeping them all.
func DumpEach(t testing.TB, module, cfg string, fn func(State)) int {
	t.Helper()
	tlc := Executable(t)
	spec := SpecDir(t)
	scratch := t.TempDir()
	entries, err := os.ReadDir(spec)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".tla") {
			b, err := os.ReadFile(filepath.Join(spec, e.Name()))
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(scratch, e.Name()), b, 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := os.WriteFile(filepath.Join(scratch, "run.cfg"), []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(tlc, "-Xmx"+Heap(), "-workers", strconv.Itoa(max(1, runtime.NumCPU()/2)), "-noGenerateSpecTE",
		"-metadir", filepath.Join(scratch, "states"), "-dump", "dump.txt", "-config", "run.cfg", module)
	cmd.Dir = scratch
	cmd.Env = AquaEnv(filepath.Dir(filepath.Dir(spec)))
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Run(); err != nil || !strings.Contains(out.String(), "No error has been found") {
		t.Fatalf("TLC failed (%v):\n%s", err, out.String())
	}
	f, err := os.Open(filepath.Join(scratch, "dump.txt.dump")) // TLC appends .dump
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	n, err := ScanDump(f, fn)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// ScanDump reads a dump state by state.
func ScanDump(r io.Reader, fn func(State)) (int, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 1<<20), 64<<20)
	var block strings.Builder
	n := 0
	emit := func() error {
		if block.Len() == 0 {
			return nil
		}
		states, err := ParseDump(block.String())
		if err != nil {
			return err
		}
		for _, s := range states {
			fn(s)
			n++
		}
		block.Reset()
		return nil
	}
	for sc.Scan() {
		line := sc.Text()
		if t := strings.TrimSpace(line); strings.HasPrefix(t, "State ") && strings.HasSuffix(t, ":") {
			if err := emit(); err != nil {
				return n, err
			}
		}
		block.WriteString(line)
		block.WriteByte('\n')
	}
	if err := sc.Err(); err != nil {
		return n, err
	}
	return n, emit()
}

// AquaEnv is the environment for running TLC outside the repository: an aqua
// proxy finds the repository's aqua.yaml through AQUA_CONFIG.
func AquaEnv(root string) []string {
	env := os.Environ()
	if os.Getenv("AQUA_CONFIG") == "" {
		if abs, err := filepath.Abs(filepath.Join(root, "aqua.yaml")); err == nil {
			if _, err := os.Stat(abs); err == nil {
				env = append(env, "AQUA_CONFIG="+abs)
			}
		}
	}
	return env
}

// Accessors that fail the test on a value of the wrong type.

func Int(t testing.TB, v Value) int64 {
	t.Helper()
	n, ok := v.(int64)
	if !ok {
		t.Fatalf("want an integer, got %#v", v)
	}
	return n
}

func Str(t testing.TB, v Value) string {
	t.Helper()
	s, ok := v.(string)
	if !ok {
		t.Fatalf("want a string, got %#v", v)
	}
	return s
}

func Bool(t testing.TB, v Value) bool {
	t.Helper()
	b, ok := v.(bool)
	if !ok {
		t.Fatalf("want a boolean, got %#v", v)
	}
	return b
}

func Rec(t testing.TB, v Value) Record {
	t.Helper()
	r, ok := v.(Record)
	if !ok {
		t.Fatalf("want a record, got %#v", v)
	}
	return r
}

func Elems(t testing.TB, v Value) []Value {
	t.Helper()
	switch x := v.(type) {
	case Set:
		return x
	case Seq:
		return x
	}
	t.Fatalf("want a set or sequence, got %#v", v)
	return nil
}

// Ints reads a set or sequence of integers, sorted.
func Ints(t testing.TB, v Value) []int64 {
	t.Helper()
	var out []int64
	for _, e := range Elems(t, v) {
		out = append(out, Int(t, e))
	}
	slices.Sort(out)
	return out
}
