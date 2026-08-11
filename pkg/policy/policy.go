// Package policy evaluates the small, deterministic authorization boundary
// used by the artifact host. Policy is deliberately separate from encryption,
// storage, and graph traversal: it receives one bounded candidate at a time.
package policy

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"
)

const (
	MaxPolicyBytes      = 256 * 1024
	DefaultEvalTimeout  = 250 * time.Millisecond
	policyQuery         = "data.enbu.allow"
	ownerOnlyPolicyName = "enbu-owner-only-v1"
)

var (
	ErrPolicyDenied    = errors.New("policy: denied")
	ErrInvalidPolicy   = errors.New("policy: invalid")
	ErrUnknownDecision = errors.New("policy: unknown decision")
	ErrPolicyTimeout   = errors.New("policy: evaluation timeout")
	ErrUnsafeBuiltin   = errors.New("policy: unsafe builtin")
)

// Identity is verified host data. It intentionally contains no arbitrary
// provider response or secret value.
type Identity struct {
	Subject  string `json:"subject"`
	DeviceID string `json:"device_id"`
	Verified bool   `json:"verified"`
}

type Workspace struct {
	ID           string `json:"id"`
	OwnerSubject string `json:"owner_subject"`
	OwnerDevice  string `json:"owner_device_id"`
}

type Target struct {
	UID         string            `json:"uid"`
	Schema      string            `json:"schema"`
	Labels      map[string]string `json:"labels,omitempty"`
	Annotations map[string]string `json:"annotations,omitempty"`
}

// Input is the complete host-controlled policy input. Parent and graph data
// are represented only by the pinned policy binding; policy cannot walk the
// artifact graph or fetch additional objects.
type Input struct {
	Action       string    `json:"action"`
	Actor        Identity  `json:"actor"`
	Candidate    Identity  `json:"candidate"`
	Workspace    Workspace `json:"workspace"`
	Target       Target    `json:"target"`
	PolicyDigest string    `json:"policy_digest"`
	ParentDigest string    `json:"parent_policy_digest,omitempty"`
	PluginDigest string    `json:"plugin_digest,omitempty"`
}

// Engine compiles and evaluates one policy per operation. Recompiling is
// intentional: policy bytes are immutable inputs and a process-global cache
// would make replacement and memory accounting harder to audit.
type Engine struct {
	timeout time.Duration
	caps    *ast.Capabilities
}

type Option func(*Engine)

func WithTimeout(timeout time.Duration) Option {
	return func(engine *Engine) {
		if timeout > 0 {
			engine.timeout = timeout
		}
	}
}

func New(options ...Option) *Engine {
	engine := &Engine{timeout: DefaultEvalTimeout, caps: safeCapabilities()}
	for _, option := range options {
		if option != nil {
			option(engine)
		}
	}
	return engine
}

// Evaluate returns true only for exactly one boolean result. Undefined,
// multiple, non-boolean, compile, and runtime results all fail closed.
func (engine *Engine) Evaluate(ctx context.Context, source []byte, input Input) (bool, error) {
	if engine == nil {
		return false, fmt.Errorf("%w: nil engine", ErrInvalidPolicy)
	}
	if ctx == nil {
		return false, fmt.Errorf("%w: nil context", ErrInvalidPolicy)
	}
	if len(source) == 0 || len(source) > MaxPolicyBytes || !utf8.Valid(source) || strings.IndexByte(string(source), 0) >= 0 {
		return false, fmt.Errorf("%w: source size or encoding", ErrInvalidPolicy)
	}
	if err := validateInput(input); err != nil {
		return false, err
	}
	if err := ctx.Err(); err != nil {
		return false, classifyContextError(err)
	}

	evalCtx, cancel := context.WithTimeout(ctx, engine.timeout)
	defer cancel()
	prepared, err := rego.New(
		rego.Query(policyQuery),
		rego.Module(ownerOnlyPolicyName+".rego", string(source)),
		rego.Capabilities(engine.caps),
		rego.StrictBuiltinErrors(true),
	).PrepareForEval(evalCtx)
	if err != nil {
		if evalCtx.Err() != nil {
			return false, classifyContextError(evalCtx.Err())
		}
		return false, fmt.Errorf("%w: compile: %v", ErrInvalidPolicy, err)
	}
	results, err := prepared.Eval(evalCtx, rego.EvalInput(input))
	if err != nil {
		if evalCtx.Err() != nil {
			return false, classifyContextError(evalCtx.Err())
		}
		return false, fmt.Errorf("%w: evaluate: %v", ErrInvalidPolicy, err)
	}
	if len(results) != 1 || len(results[0].Expressions) != 1 {
		return false, ErrUnknownDecision
	}
	decision, ok := results[0].Expressions[0].Value.(bool)
	if !ok {
		return false, ErrUnknownDecision
	}
	if !decision {
		return false, ErrPolicyDenied
	}
	return true, nil
}

func classifyContextError(err error) error {
	if errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("%w: %v", ErrPolicyTimeout, err)
	}
	return err
}

func validateInput(input Input) error {
	if input.Action == "" || len(input.Action) > 128 || strings.IndexByte(input.Action, 0) >= 0 {
		return fmt.Errorf("%w: action", ErrInvalidPolicy)
	}
	for name, value := range map[string]string{
		"actor subject":        input.Actor.Subject,
		"actor device":         input.Actor.DeviceID,
		"candidate subject":    input.Candidate.Subject,
		"candidate device":     input.Candidate.DeviceID,
		"workspace id":         input.Workspace.ID,
		"target uid":           input.Target.UID,
		"target schema":        input.Target.Schema,
		"policy digest":        input.PolicyDigest,
		"parent policy digest": input.ParentDigest,
		"plugin digest":        input.PluginDigest,
	} {
		if len(value) > 512 || strings.IndexByte(value, 0) >= 0 {
			return fmt.Errorf("%w: %s", ErrInvalidPolicy, name)
		}
	}
	if len(input.Target.Labels) > 256 || len(input.Target.Annotations) > 256 {
		return fmt.Errorf("%w: target metadata count", ErrInvalidPolicy)
	}
	return nil
}

// OwnerOnlyPolicy is the initialization policy. The host supplies verified
// owner identity fields; no policy can manufacture them.
func OwnerOnlyPolicy() []byte {
	return []byte(`package enbu
import rego.v1

default allow := false

allow if {
  input.action == "workspace.initialize"
  input.actor.verified
  input.actor.subject == input.workspace.owner_subject
  input.actor.device_id == input.workspace.owner_device_id
}

allow if {
  input.action == "grant.add"
  input.actor.verified
  input.actor.subject == input.workspace.owner_subject
  input.actor.device_id == input.workspace.owner_device_id
  input.candidate.verified
}`)
}

// safeCapabilities starts from the parser/runtime's current capability set
// and removes every side-effecting or nondeterministic builtin. Keeping the
// pure standard library avoids an unnecessarily tiny, surprising policy DSL.
func safeCapabilities() *ast.Capabilities {
	base := ast.CapabilitiesForThisVersion()
	unsafe := func(name string) bool {
		for _, prefix := range []string{"http.", "net.", "io.", "opa.runtime", "time.now", "rand.", "uuid.", "crypto.x509"} {
			if strings.HasPrefix(name, prefix) {
				return true
			}
		}
		switch name {
		case "print", "trace":
			return true
		default:
			return false
		}
	}
	filtered := make([]*ast.Builtin, 0, len(base.Builtins))
	for _, builtin := range base.Builtins {
		if builtin != nil && !unsafe(builtin.Name) {
			copy := *builtin
			filtered = append(filtered, &copy)
		}
	}
	base.Builtins = filtered
	base.AllowNet = []string{}
	return base
}
