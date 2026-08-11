// Package client contains the protocol-neutral adapters used by the CLI,
// Bubble Tea, and Wails frontends. It deliberately exposes operation state,
// not resource payloads: payload access stays inside the application host.
package client

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/enbu-net/enbu/pkg/host"
)

var (
	ErrNilController    = errors.New("client: nil controller")
	ErrUnknownOperation = errors.New("client: unknown operation")
)

// Operation is the client-safe view of a host operation. Progress intentionally
// omits the reporter message so a client cannot accidentally render a secret
// or an arbitrary plugin error.
type Operation struct {
	ID       string
	Progress <-chan Event
	Done     <-chan Result
}

type Event struct {
	OperationID string `json:"operation_id"`
	Sequence    uint64 `json:"sequence"`
	Phase       string `json:"phase"`
}

type Result struct {
	OperationID string
	Err         error
}

type trackedOperation struct {
	cancel context.CancelFunc
	op     host.Operation
}

// Controller binds one immutable host session to a client. A controller is
// safe for concurrent calls and owns cancellation for all started operations.
type Controller struct {
	host    *host.Host
	session host.Session

	mu         sync.Mutex
	operations map[string]trackedOperation
}

func NewController(h *host.Host, session host.Session) (*Controller, error) {
	if h == nil || session.WorkspaceID() == "" {
		return nil, fmt.Errorf("%w: host and session are required", ErrNilController)
	}
	return &Controller{host: h, session: session, operations: make(map[string]trackedOperation)}, nil
}

func (c *Controller) Session() host.Session {
	if c == nil {
		return host.Session{}
	}
	return c.session
}

func (c *Controller) Start(ctx context.Context, action string, run host.Action) (Operation, error) {
	if c == nil {
		return Operation{}, ErrNilController
	}
	if ctx == nil {
		return Operation{}, host.ErrInvalidAction
	}
	runCtx, cancel := context.WithCancel(ctx)
	op, err := c.host.Start(runCtx, c.session, action, run)
	if err != nil {
		cancel()
		return Operation{}, err
	}
	id := string(op.ID)
	events := make(chan Event, 32)
	done := make(chan Result, 1)
	c.mu.Lock()
	c.operations[id] = trackedOperation{cancel: cancel, op: op}
	c.mu.Unlock()
	go func() {
		defer close(events)
		for progress := range op.Progress {
			events <- Event{OperationID: string(progress.OperationID), Sequence: progress.Sequence, Phase: progress.Phase}
		}
	}()
	go func() {
		result, ok := <-op.Done
		if !ok {
			result = host.Result{OperationID: op.ID, Err: errors.New("host: operation closed without result")}
		}
		done <- Result{OperationID: string(result.OperationID), Err: result.Err}
		close(done)
	}()
	return Operation{ID: id, Progress: events, Done: done}, nil
}

func (c *Controller) Cancel(id string) error {
	if c == nil {
		return ErrNilController
	}
	c.mu.Lock()
	tracked, ok := c.operations[id]
	c.mu.Unlock()
	if !ok {
		return fmt.Errorf("%w: %s", ErrUnknownOperation, id)
	}
	tracked.cancel()
	return nil
}

// Wait consumes a result and removes the operation from the controller. The
// returned error is the host action's error; callers should log it rather than
// expose its text through a frontend protocol.
func (c *Controller) Wait(ctx context.Context, op Operation) error {
	if ctx == nil {
		return host.ErrInvalidAction
	}
	select {
	case result := <-op.Done:
		c.mu.Lock()
		delete(c.operations, op.ID)
		c.mu.Unlock()
		return result.Err
	case <-ctx.Done():
		return ctx.Err()
	}
}

// RunCLI executes one operation and writes only safe phase markers. It is the
// canonical CLI adapter; payloads and host error details never enter stdout.
func (c *Controller) RunCLI(ctx context.Context, action string, run host.Action, out io.Writer) error {
	if out == nil {
		return errors.New("client: nil output")
	}
	op, err := c.Start(ctx, action, run)
	if err != nil {
		return err
	}
	for event := range op.Progress {
		if _, err := fmt.Fprintf(out, "%s\n", event.Phase); err != nil {
			_ = c.Cancel(op.ID)
			return err
		}
	}
	return c.Wait(ctx, op)
}
