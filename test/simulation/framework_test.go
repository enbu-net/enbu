package simulation

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"testing"

	"github.com/enbu-net/enbu/pkg/storage"
	"github.com/enbu-net/enbu/pkg/storage/storagetest"
)

func TestStoreContract(t *testing.T) {
	storagetest.Contract(t, &Store{Store: storagetest.NewMemory(), Tape: NewTape(0, "")})
}
func TestTapeStrictness(t *testing.T) {
	source := NewTape(1, "")
	var out string
	if e := source.Value("crypto", []string{"input"}, func() (any, error) { return "ciphertext", nil }, &out); e != nil {
		t.Fatal(e)
	}
	for _, tc := range []string{"input", "kind", "output", "missing", "extra"} {
		t.Run(tc, func(t *testing.T) {
			b, _ := json.Marshal(source.Recording)
			var r Recording
			_ = json.Unmarshal(b, &r)
			tape := &Tape{Recording: r, Replay: true}
			var e error
			switch tc {
			case "input":
				e = tape.Value("crypto", nil, nil, &out)
			case "kind":
				e = tape.Value("wrong", []string{"input"}, nil, &out)
			case "output":
				e = tape.Observe("crypto", []string{"input"}, "changed")
			case "missing":
				e = tape.Finish()
			case "extra":
				_ = tape.Value("crypto", []string{"input"}, nil, &out)
				e = tape.Value("crypto", []string{"input"}, nil, &out)
			}
			if e == nil {
				t.Fatal("invalid replay accepted")
			}
		})
	}
}
func TestSchedulerReplaysExactInterleaving(t *testing.T) {
	tape := NewTape(99, "")
	run := func(tape *Tape) []string {
		var trace []string
		var jobs []func(*Actor) error
		for i := 0; i < 4; i++ {
			jobs = append(jobs, func(a *Actor) error {
				for j := 0; j < 4; j++ {
					if e := a.Boundary("io", func() error { trace = append(trace, string(rune('a'+i))); return nil }); e != nil {
						return e
					}
				}
				return nil
			})
		}
		errs, e := NewScheduler(tape).Run(context.Background(), jobs)
		if e != nil {
			t.Fatal(e)
		}
		for _, e := range errs {
			if e != nil {
				t.Fatal(e)
			}
		}
		if e := tape.Finish(); e != nil {
			t.Fatal(e)
		}
		return trace
	}
	want := run(tape)
	for i := 0; i < 10; i++ {
		replay := &Tape{Recording: tape.Recording, Replay: true}
		if got := run(replay); !reflect.DeepEqual(got, want) {
			t.Fatalf("trace changed: %v %v", want, got)
		}
	}
}
func TestAmbiguousPublishIsDurable(t *testing.T) {
	s := &Store{Store: storagetest.NewMemory(), Tape: NewTape(0, "")}
	s.Arm(Fault{"publish", 1, "after"})
	o := storagetest.Object(storage.KindControl, "", "control", "")
	if e := s.Publish(context.Background(), o); !errors.Is(e, ErrOffline) {
		t.Fatal(e)
	}
	if _, e := s.FetchHead(context.Background(), o.Kind, o.Scope, o.Rev); e != nil {
		t.Fatal(e)
	}
}

func TestActualCancellationStopsLaterEffects(t *testing.T) {
	for _, mode := range []string{"context-before", "context-after"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			base := storagetest.NewMemory()
			s := &Store{Store: base, Tape: NewTape(0, ""), cancel: cancel}
			s.Arm(Fault{"publish", 1, mode})
			first := storagetest.Object(storage.KindControl, "", "first", "")
			if err := s.Publish(ctx, first); !errors.Is(err, context.Canceled) || !errors.Is(ctx.Err(), context.Canceled) {
				t.Fatalf("operation context was not canceled: result=%v context=%v", err, ctx.Err())
			}
			_, err := base.FetchHead(t.Context(), first.Kind, first.Scope, first.Rev)
			if mode == "context-before" && !errors.Is(err, storage.ErrNotFound) || mode == "context-after" && err != nil {
				t.Fatalf("wrong durable side of cancellation: %v", err)
			}
			second := storagetest.Object(storage.KindControl, "", "second", "")
			if err := s.Publish(ctx, second); !errors.Is(err, context.Canceled) {
				t.Fatalf("subsequent call ignored cancellation: %v", err)
			}
			if _, err := base.FetchHead(t.Context(), second.Kind, second.Scope, second.Rev); !errors.Is(err, storage.ErrNotFound) {
				t.Fatalf("subsequent call had a durable effect: %v", err)
			}
		})
	}
}
func TestOracleDetectsLostWrite(t *testing.T) {
	w, e := NewWorld(t.TempDir(), NewTape(0, ""), 2)
	if e != nil {
		t.Fatal(e)
	}
	if e := w.Bootstrap(context.Background()); e != nil {
		t.Fatal(e)
	}
	// A deliberately lost acknowledged update must fail independently of merge.
	w.Model["default"]["LOST"] = "acknowledged"
	err := w.Check(context.Background(), "default")
	var violation *Violation
	if !errors.As(err, &violation) || violation.Kind != "model/default/LOST" {
		t.Fatalf("oracle did not identify the lost-key property: %v", err)
	}
}
