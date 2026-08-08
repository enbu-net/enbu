package policy

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func testInput() Input {
	return Input{
		Action:    "grant.add",
		Actor:     Identity{Subject: "github:owner", DeviceID: "device-owner", Verified: true},
		Candidate: Identity{Subject: "github:member", DeviceID: "device-member", Verified: true},
		Workspace: Workspace{ID: "workspace", OwnerSubject: "github:owner", OwnerDevice: "device-owner"},
		Target:    Target{UID: "uid", Schema: "schemas.enbu.net/SecretMap"},
	}
}

func TestOwnerOnlyPolicy(t *testing.T) {
	engine := New()
	allowed, err := engine.Evaluate(context.Background(), OwnerOnlyPolicy(), testInput())
	if err != nil || !allowed {
		t.Fatalf("owner policy = %v, %v", allowed, err)
	}
	input := testInput()
	input.Actor.DeviceID = "different-device"
	if allowed, err := engine.Evaluate(context.Background(), OwnerOnlyPolicy(), input); !errors.Is(err, ErrPolicyDenied) || allowed {
		t.Fatalf("owner mismatch = %v, %v", allowed, err)
	}
}

func TestPolicyUndefinedAndNonBooleanDeny(t *testing.T) {
	engine := New()
	for name, source := range map[string]string{
		"undefined": `package enbu
import rego.v1
allow if input.actor.subject == "nobody"`,
		"nonboolean": `package enbu
import rego.v1
allow := "yes"`,
	} {
		t.Run(name, func(t *testing.T) {
			allowed, err := engine.Evaluate(context.Background(), []byte(source), testInput())
			if allowed || !errors.Is(err, ErrUnknownDecision) {
				t.Fatalf("decision = %v, %v", allowed, err)
			}
		})
	}
}

func TestPolicyRejectsSideEffectingBuiltinsAtCompile(t *testing.T) {
	engine := New()
	for _, builtin := range []string{"http.send", "time.now_ns", "opa.runtime", "rand.intn"} {
		t.Run(builtin, func(t *testing.T) {
			source := []byte("package enbu\nimport rego.v1\nallow if { " + builtin + "(\"x\") }")
			allowed, err := engine.Evaluate(context.Background(), source, testInput())
			if allowed || !errors.Is(err, ErrInvalidPolicy) {
				t.Fatalf("decision = %v, %v", allowed, err)
			}
		})
	}
}

func TestPolicyBoundsAndCancellation(t *testing.T) {
	engine := New(WithTimeout(time.Millisecond))
	if _, err := engine.Evaluate(context.Background(), make([]byte, MaxPolicyBytes+1), testInput()); !errors.Is(err, ErrInvalidPolicy) {
		t.Fatalf("oversized policy error = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := engine.Evaluate(ctx, OwnerOnlyPolicy(), testInput()); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled policy error = %v", err)
	}
	deadline, cancel := context.WithTimeout(context.Background(), time.Nanosecond)
	defer cancel()
	time.Sleep(time.Millisecond)
	if _, err := engine.Evaluate(deadline, OwnerOnlyPolicy(), testInput()); !errors.Is(err, ErrPolicyTimeout) {
		t.Fatalf("deadline policy error = %v", err)
	}
}

func TestPolicyInputRejectsNULAndOversizedMetadata(t *testing.T) {
	engine := New()
	input := testInput()
	input.Action = strings.Repeat("x", 129)
	if _, err := engine.Evaluate(context.Background(), OwnerOnlyPolicy(), input); !errors.Is(err, ErrInvalidPolicy) {
		t.Fatalf("oversized action error = %v", err)
	}
	input = testInput()
	input.Target.Labels = make(map[string]string, 257)
	for index := 0; index < 257; index++ {
		input.Target.Labels[strings.Repeat("k", index+1)] = "v"
	}
	if _, err := engine.Evaluate(context.Background(), OwnerOnlyPolicy(), input); !errors.Is(err, ErrInvalidPolicy) {
		t.Fatalf("oversized labels error = %v", err)
	}
}
