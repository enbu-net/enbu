// Package simulation drives real enbu operations under a controlled schedule.
package simulation

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"
)

type Entry struct {
	Kind   string
	Input  json.RawMessage
	Output json.RawMessage
}
type Recording struct {
	Format   string
	Revision string
	Seed     uint64
	Entries  []Entry
}

// Tape is single-owner: the scheduler permits only one actor to run between
// external boundaries. Entries are consumed strictly, never searched or skipped.
type Tape struct {
	// Journal preserves the executed prefix even when a timeout terminates Go.
	Journal   io.Writer
	plan      *Plan
	mu        sync.Mutex
	Recording Recording
	Replay    bool
	cursor    int
	failure   error
}

func NewTape(seed uint64, revision string) *Tape {
	return &Tape{Recording: Recording{Format: "enbu-simulation-v1", Seed: seed, Revision: revision}}
}
func LoadTape(path string) (*Tape, error) {
	b, e := os.ReadFile(path)
	if e != nil {
		return nil, e
	}
	var r Recording
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if e = dec.Decode(&r); e != nil {
		return nil, e
	}
	if r.Format != "enbu-simulation-v1" {
		return nil, fmt.Errorf("unsupported recording format %q", r.Format)
	}
	var trailing any
	if e := dec.Decode(&trailing); e != io.EOF {
		return nil, fmt.Errorf("trailing recording content: %v", e)
	}
	for i := range r.Entries {
		var input, output bytes.Buffer
		if e := json.Compact(&input, r.Entries[i].Input); e != nil {
			return nil, e
		}
		if e := json.Compact(&output, r.Entries[i].Output); e != nil {
			return nil, e
		}
		r.Entries[i].Input = input.Bytes()
		r.Entries[i].Output = output.Bytes()
	}
	return &Tape{Recording: r, Replay: true}, nil
}
func (t *Tape) Save(path string) error {
	b, e := json.MarshalIndent(t.Recording, "", "  ")
	if e != nil {
		return e
	}
	return os.WriteFile(path, b, 0600)
}
func (t *Tape) Value(kind string, input any, generate func() (any, error), output any) (err error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.failure != nil {
		return t.failure
	}
	defer func() {
		if err != nil {
			t.failure = err
		}
	}()
	in, e := json.Marshal(input)
	if e != nil {
		return e
	}
	if t.Replay {
		if t.cursor >= len(t.Recording.Entries) {
			return fmt.Errorf("tape exhausted at %s", kind)
		}
		entry := t.Recording.Entries[t.cursor]
		t.cursor++
		if entry.Kind != kind || !bytes.Equal(entry.Input, in) {
			return fmt.Errorf("tape entry %d: expected %s %s, got %s %s", t.cursor-1, entry.Kind, entry.Input, kind, in)
		}
		return json.Unmarshal(entry.Output, output)
	}
	v, e := generate()
	if e != nil {
		return e
	}
	out, e := json.Marshal(v)
	if e != nil {
		return e
	}
	entry := Entry{kind, in, out}
	t.Recording.Entries = append(t.Recording.Entries, entry)
	if t.Journal != nil {
		if e := json.NewEncoder(t.Journal).Encode(entry); e != nil {
			return e
		}
	}
	return json.Unmarshal(out, output)
}
func (t *Tape) Observe(kind string, input, actual any) error {
	var expected json.RawMessage
	if e := t.Value(kind, input, func() (any, error) { return actual, nil }, &expected); e != nil {
		return e
	}
	got, e := json.Marshal(actual)
	if e != nil {
		return e
	}
	if !bytes.Equal(expected, got) {
		e := fmt.Errorf("%s: expected %s, got %s", kind, expected, got)
		t.mu.Lock()
		t.failure = e
		t.mu.Unlock()
		return e
	}
	return nil
}
func (t *Tape) Finish() error {
	if t.failure != nil {
		return t.failure
	}
	if t.Replay && t.cursor != len(t.Recording.Entries) {
		return fmt.Errorf("%d unconsumed tape entries", len(t.Recording.Entries)-t.cursor)
	}
	return nil
}
