package simulation

import (
	"context"
	"fmt"
)

type Plan struct {
	AuthorityAttack string
	Acceptance      *AcceptanceCase
	CompactionRace  *CompactionRaceCase
	Clock           string
	Compound        *CompoundCase
	Swarm           string
	MergeCase       *MergeCase
	AdminRace       string
	Team            *TeamCase
	Concurrent      *ConcurrentCase
	StateCase       *StateCase
	FoundingFault   *Fault
	Probe           *Probe
	Devices         int
	Scenario        string
	Actions         []Action
}

// Execute consumes the recorded plan, including bootstrap, on a fresh root.
func Execute(ctx context.Context, tape *Tape, root string) error {
	var plan Plan
	if e := tape.Value("plan", nil, func() (any, error) {
		if tape.plan == nil {
			return nil, fmt.Errorf("no plan")
		}
		return *tape.plan, nil
	}, &plan); e != nil {
		return e
	}
	// Bound untrusted replay plans while permitting larger-team stress cases.
	if plan.Devices < 2 || plan.Devices > 32 {
		return fmt.Errorf("invalid device count %d", plan.Devices)
	}
	switch plan.Clock {
	case "", "frozen", "backward", "skewed":
	default:
		return fmt.Errorf("invalid clock profile %q", plan.Clock)
	}
	for index, op := range plan.Actions {
		if op.Device < 0 || op.Device >= plan.Devices {
			return fmt.Errorf("action %d: invalid device %d", index, op.Device)
		}
	}
	w, e := NewWorld(root, tape, plan.Devices)
	if e != nil {
		return e
	}
	w.Clock = plan.Clock
	if plan.FoundingFault != nil {
		if _, err := w.FoundingProbe(ctx, *plan.FoundingFault); err != nil {
			return err
		}
		return tape.Finish()
	}
	if plan.Scenario == "first-member" {
		if err := w.FirstMember(ctx); err != nil {
			return err
		}
	} else if e := w.Bootstrap(ctx); e != nil {
		return e
	}
	if plan.AuthorityAttack != "" {
		if err := w.AuthorityAttack(ctx, plan.AuthorityAttack); err != nil {
			return err
		}
	}
	if plan.Acceptance != nil {
		if err := w.AcceptanceCase(ctx, *plan.Acceptance); err != nil {
			return err
		}
	}
	if plan.CompactionRace != nil {
		if err := w.CompactionRace(ctx, *plan.CompactionRace); err != nil {
			return err
		}
	}
	if plan.Compound != nil {
		if err := w.Compound(ctx, *plan.Compound); err != nil {
			return err
		}
	}
	if plan.Swarm != "" {
		if err := w.Swarm(ctx, plan.Swarm); err != nil {
			return err
		}
	}
	if plan.MergeCase != nil {
		if err := w.MergeCase(ctx, *plan.MergeCase); err != nil {
			return err
		}
	}
	if plan.AdminRace != "" {
		if err := w.AdminRace(ctx, plan.AdminRace); err != nil {
			return err
		}
	}
	if plan.Team != nil {
		if err := w.TeamCase(ctx, *plan.Team); err != nil {
			return err
		}
	}
	if plan.Concurrent != nil {
		if err := w.ConcurrentCase(ctx, *plan.Concurrent); err != nil {
			return err
		}
	}
	if plan.StateCase != nil {
		if err := w.StateCase(ctx, *plan.StateCase); err != nil {
			return err
		}
	}
	if plan.Probe != nil {
		if _, e := w.Probe(ctx, *plan.Probe); e != nil {
			return e
		}
	}
	if plan.Scenario != "" && plan.Scenario != "first-member" {
		if e := w.Scenario(ctx, plan.Scenario); e != nil {
			return fmt.Errorf("scenario %s: %w", plan.Scenario, e)
		}
	}
	if e := w.Workload(ctx, plan.Actions); e != nil {
		return e
	}
	if e := tape.Observe("final-model", nil, w.Model); e != nil {
		return e
	}
	return tape.Finish()
}

// Prepare writes the explicit operation sequence before execution. Shrinking
// produces a fresh recording; it never skips mismatched entries in a replay.
func Prepare(seed uint64, revision string, plan Plan) (*Tape, error) {
	tape := NewTape(seed, revision)
	tape.plan = &plan
	return tape, nil
}

// Minimize removes chunks, keeping a candidate only if the same failure remains.
func Minimize(actions []Action, fails func([]Action) bool) []Action {
	if fails(nil) {
		return nil
	}
	current := append([]Action(nil), actions...)
	for size := len(current) / 2; size > 0; size /= 2 {
		for start := 0; start+size <= len(current); {
			candidate := append([]Action(nil), current[:start]...)
			candidate = append(candidate, current[start+size:]...)
			if fails(candidate) {
				current = candidate
			} else {
				start += size
			}
		}
	}
	return current
}

// Violation identifies an oracle failure independently of operation indices,
// allowing shrinking to preserve the property that failed.
type Violation struct {
	Kind   string
	Detail error
}

func (v *Violation) Error() string { return v.Kind + ": " + v.Detail.Error() }
func (v *Violation) Unwrap() error { return v.Detail }
