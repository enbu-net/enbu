package tla

import (
	"reflect"
	"strings"
	"testing"
)

func TestParseValues(t *testing.T) {
	cases := map[string]Value{
		`42`:                       int64(42),
		`-1`:                       int64(-1),
		`"a \"b\""`:                `a "b"`,
		`TRUE`:                     true,
		`{}`:                       Set(nil),
		`{1, 2}`:                   Set{int64(1), int64(2)},
		`<<"x", {3}>>`:             Seq{"x", Set{int64(3)}},
		`[a |-> 1, b |-> {"r"}]`:   Record{"a": int64(1), "b": Set{"r"}},
		` [ x |-> [y |-> FALSE] ]`: Record{"x": Record{"y": false}},
	}
	for in, want := range cases {
		got, err := Parse(in)
		if err != nil {
			t.Fatalf("%s: %v", in, err)
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%s: got %#v, want %#v", in, got, want)
		}
	}
	for _, bad := range []string{`{1, }`, `[a 1]`, `"open`, `{1} 2`, `@`, `[ |-> 1]`} {
		if _, err := Parse(bad); err == nil {
			t.Errorf("%q should not parse", bad)
		}
	}
}

func TestParseDump(t *testing.T) {
	dump := `State 1:
/\ x = 0
/\ s = { [ id |-> 0,
    parents |-> {} ] }

State 2:
/\ x = 1
/\ s = {}
`
	states, err := ParseDump(dump)
	if err != nil {
		t.Fatal(err)
	}
	if len(states) != 2 {
		t.Fatalf("want 2 states, got %d", len(states))
	}
	if Int(t, states[1]["x"]) != 1 {
		t.Fatalf("state 2: %#v", states[1])
	}
	s := Elems(t, states[0]["s"])
	if len(s) != 1 || Int(t, Rec(t, s[0])["id"]) != 0 || len(Elems(t, Rec(t, s[0])["parents"])) != 0 {
		t.Fatalf("multi-line value: %#v", states[0]["s"])
	}
	var scanned []State
	if n, err := ScanDump(strings.NewReader(dump), func(s State) { scanned = append(scanned, s) }); err != nil || n != 2 || !reflect.DeepEqual(scanned, states) {
		t.Fatalf("streaming gives %d states (%v), want the same as ParseDump", n, err)
	}
	if _, err := ParseDump("State 1:\n/\\ x = {\n"); err == nil {
		t.Fatal("a truncated value must fail")
	}
}

func TestDumpRunsTLC(t *testing.T) {
	states := Dump(t, "Founding.tla", `CONSTANTS
    Workspaces = {"w1"}
    AttackerActs = FALSE
    OtherFounds = FALSE
    MaxCrashes = 0
    MaxEdits = 0
    Mutant = "none"
SPECIFICATION Spec
CHECK_DEADLOCK FALSE
`)
	if len(states) < 5 {
		t.Fatalf("expected the founding steps, got %d states", len(states))
	}
	sawSession := false
	for _, s := range states {
		if Str(t, Rec(t, s["session"])["ws"]) == "w1" {
			sawSession = true
		}
	}
	if !sawSession {
		t.Fatal("the dump never reaches a session")
	}
}
