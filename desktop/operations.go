package desktop

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/enbu-net/enbu/pkg/apperr"
	"github.com/enbu-net/enbu/pkg/client"
	"github.com/enbu-net/enbu/pkg/host"
)

const maxPollEvents = 64

// HostOperationStatus is safe to expose through Wails. It contains no
// reporter message, payload value, path, or arbitrary error text.
type HostOperationStatus struct {
	OperationID string         `json:"operation_id"`
	Events      []client.Event `json:"events,omitempty"`
	Done        bool           `json:"done"`
	ErrorCode   string         `json:"error_code,omitempty"`
}

type HostOperationStart struct {
	OperationID string `json:"operation_id"`
}

// HostOperations is the trusted desktop adapter for the shared application
// host. Actions are registered by Go code; a frontend can only select a name.
type HostOperations struct {
	controller *client.Controller

	mu      sync.Mutex
	actions map[string]host.Action
	active  map[string]client.Operation
}

func (s *Service) SetHostOperations(operations *HostOperations) {
	if s == nil {
		return
	}
	s.hostOps = operations
}

func (s *Service) StartHostOperation(name string) (HostOperationStart, error) {
	if s == nil || s.hostOps == nil {
		return HostOperationStart{}, errors.New("desktop: host operations are unavailable")
	}
	return s.hostOps.Start(s.context(), name)
}

func (s *Service) PollHostOperation(id string) (HostOperationStatus, error) {
	if s == nil || s.hostOps == nil {
		return HostOperationStatus{}, errors.New("desktop: host operations are unavailable")
	}
	return s.hostOps.Poll(id)
}

func (s *Service) CancelHostOperation(id string) error {
	if s == nil || s.hostOps == nil {
		return errors.New("desktop: host operations are unavailable")
	}
	return s.hostOps.Cancel(id)
}

func NewHostOperations(controller *client.Controller) *HostOperations {
	return &HostOperations{controller: controller, actions: make(map[string]host.Action), active: make(map[string]client.Operation)}
}

func (operations *HostOperations) Register(name string, action host.Action) error {
	if operations == nil || operations.controller == nil {
		return errors.New("desktop: host controller is unavailable")
	}
	if name == "" || len(name) > host.MaxProgressMessage || action == nil {
		return host.ErrInvalidAction
	}
	operations.mu.Lock()
	defer operations.mu.Unlock()
	if _, exists := operations.actions[name]; exists {
		return fmt.Errorf("desktop: action %q is already registered", name)
	}
	operations.actions[name] = action
	return nil
}

func (operations *HostOperations) Start(ctx context.Context, name string) (HostOperationStart, error) {
	if operations == nil || operations.controller == nil {
		return HostOperationStart{}, errors.New("desktop: host controller is unavailable")
	}
	if ctx == nil {
		return HostOperationStart{}, host.ErrInvalidAction
	}
	operations.mu.Lock()
	action, ok := operations.actions[name]
	operations.mu.Unlock()
	if !ok {
		return HostOperationStart{}, fmt.Errorf("desktop: unknown host action %q", name)
	}
	op, err := operations.controller.Start(ctx, name, action)
	if err != nil {
		return HostOperationStart{}, err
	}
	operations.mu.Lock()
	operations.active[op.ID] = op
	operations.mu.Unlock()
	return HostOperationStart{OperationID: op.ID}, nil
}

func (operations *HostOperations) Poll(id string) (HostOperationStatus, error) {
	if operations == nil {
		return HostOperationStatus{}, errors.New("desktop: host operations are unavailable")
	}
	operations.mu.Lock()
	op, ok := operations.active[id]
	operations.mu.Unlock()
	if !ok {
		return HostOperationStatus{}, fmt.Errorf("desktop: unknown operation %q", id)
	}
	status := HostOperationStatus{OperationID: id, Events: make([]client.Event, 0, maxPollEvents)}
	for len(status.Events) < maxPollEvents {
		select {
		case event, open := <-op.Progress:
			if !open {
				status.Done = true
				select {
				case result := <-op.Done:
					if result.Err != nil {
						status.ErrorCode = string(apperr.PayloadOf(apperr.Normalize(result.Err)).Code)
					}
				default:
				}
				operations.mu.Lock()
				delete(operations.active, id)
				operations.mu.Unlock()
				return status, nil
			}
			status.Events = append(status.Events, event)
		default:
			return status, nil
		}
	}
	return status, nil
}

func (operations *HostOperations) Cancel(id string) error {
	if operations == nil || operations.controller == nil {
		return errors.New("desktop: host operations are unavailable")
	}
	return operations.controller.Cancel(id)
}
