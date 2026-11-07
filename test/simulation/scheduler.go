package simulation

import (
	"context"
	"fmt"
	"math/rand/v2"
	"runtime/debug"
	"sort"
	"sync"
)

type request struct {
	name   string
	run    func() error
	resume chan error
	done   bool
	err    error
}
type Actor struct {
	id     int
	events chan request
	ctx    context.Context
}

// Boundary blocks until the scheduler executes this external effect. No timer
// or goroutine race determines which request executes next.
func (a *Actor) Boundary(name string, run func() error) error {
	r := request{name: name, run: run, resume: make(chan error)}
	select {
	case a.events <- r:
	case <-a.ctx.Done():
		return a.ctx.Err()
	}
	select {
	case e := <-r.resume:
		return e
	case <-a.ctx.Done():
		return a.ctx.Err()
	}
}

type Scheduler struct {
	// Hold defers this boundary while another actor can reach it, forcing a race.
	Hold string

	Tape *Tape
	rng  *rand.Rand
}

func NewScheduler(t *Tape) *Scheduler {
	return &Scheduler{Tape: t, rng: rand.New(rand.NewPCG(t.Recording.Seed, 0x5343484544))}
}

// Run allows at most one actor to execute Go code at a time, collecting its next
// boundary before choosing another actor. Effects are executed on this goroutine.
func (s *Scheduler) Run(ctx context.Context, jobs []func(*Actor) error) ([]error, error) {
	ctx, cancel := context.WithCancel(ctx)
	var wg sync.WaitGroup
	defer func() { cancel(); wg.Wait() }()
	actors := make([]*Actor, len(jobs))
	pending := map[int]request{}
	results := make([]error, len(jobs))
	receive := func(i int) error {
		select {
		case r := <-actors[i].events:
			if r.done {
				results[i] = r.err
			} else {
				pending[i] = r
			}
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	for i, job := range jobs {
		a := &Actor{id: i, events: make(chan request), ctx: ctx}
		actors[i] = a
		wg.Add(1)
		go func() {
			defer wg.Done()
			var e error
			func() {
				defer func() {
					if r := recover(); r != nil {
						if r == ErrCrash {
							e = ErrCrash
						} else {
							e = fmt.Errorf("actor panic: %v\n%s", r, debug.Stack())
						}
					}
				}()
				e = job(a)
			}()
			select {
			case a.events <- request{done: true, err: e}:
			case <-ctx.Done():
			}
		}()
		if e := receive(i); e != nil {
			return nil, e
		}
	}
	for len(pending) > 0 {
		ids := make([]int, 0, len(pending))
		for i := range pending {
			ids = append(ids, i)
		}
		sort.Ints(ids)
		if s.Hold != "" {
			var free []int
			for _, i := range ids {
				if pending[i].name != s.Hold {
					free = append(free, i)
				}
			}
			if len(free) > 0 {
				ids = free
			}
		}
		chosen := 0
		if e := s.Tape.Value("schedule", ids, func() (any, error) { return ids[s.rng.IntN(len(ids))], nil }, &chosen); e != nil {
			return nil, e
		}
		r, ok := pending[chosen]
		if !ok {
			return nil, fmt.Errorf("recorded actor %d is not runnable", chosen)
		}
		delete(pending, chosen)
		if e := s.Tape.Observe("boundary", chosen, r.name); e != nil {
			return nil, e
		}
		e := r.run()
		select {
		case r.resume <- e:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		if e := receive(chosen); e != nil {
			return nil, e
		}
	}
	return results, nil
}
