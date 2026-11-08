package simulation

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"testing"
)

func TestOperationFaultMatrix(t *testing.T) {
	exploration(t)
	for index, op := range ProbeOperations {
		if !ownsIndex(t, index) {
			continue
		}
		t.Run(op, func(t *testing.T) {
			measured := baseline(t, 999, Plan{Devices: 3, Probe: &Probe{Operation: op}})
			counts := countsBetween(t, measured, "probe-start", "probe-result")
			methods := make([]string, 0, len(counts))
			for method := range counts {
				methods = append(methods, method)
			}
			sort.Strings(methods)
			for _, method := range methods {
				occurrences := []int{1}
				if counts[method] > 1 {
					occurrences = append(occurrences, counts[method])
				}
				if os.Getenv("ENBU_SIM_EXHAUSTIVE") == "1" {
					occurrences = nil
					for i := 1; i <= counts[method]; i++ {
						occurrences = append(occurrences, i)
					}
				}
				modes := []string{"before", "cancel", "context-before", "crash-before"}
				if method == "publish" || method == "delete" {
					modes = append(modes, "after", "context-after", "crash-after")
				}
				for _, at := range occurrences {
					for _, mode := range modes {
						t.Run(fmt.Sprintf("%s-%d-%s", method, at, mode), func(t *testing.T) { exercise(t, 999, Plan{Devices: 3, Probe: &Probe{op, Fault{method, at, mode}}}) })
					}
				}
			}
		})
	}
}

func countsBetween(t *testing.T, tape *Tape, start, end string) map[string]int {
	t.Helper()
	inside := false
	counts := map[string]int{}
	for _, entry := range tape.Recording.Entries {
		if entry.Kind == start {
			inside = true
			continue
		}
		if inside && entry.Kind == end {
			break
		}
		if inside && entry.Kind == "storage-request" {
			var request struct{ Method string }
			if err := json.Unmarshal(entry.Output, &request); err != nil {
				t.Fatal(err)
			}
			counts[request.Method]++
		}
	}
	if len(counts) == 0 {
		t.Fatal("baseline contains no measured storage calls")
	}
	return counts
}
func TestWildcardFaultProbeIsReachable(t *testing.T) {
	exercise(t, 999, Plan{Devices: 3, Probe: &Probe{Operation: "add", Fault: Fault{"*", 1, "before"}}})
}

func TestActualContextCancellationRecovery(t *testing.T) {
	for _, op := range []string{"edit", "approve", "remove", "upgrade", "compact", "purge", "pull-file"} {
		t.Run(op, func(t *testing.T) {
			measured := baseline(t, 79, Plan{Devices: 3, Probe: &Probe{Operation: op}})
			counts := countsBetween(t, measured, "probe-start", "probe-result")
			methods := []string{"publish", "delete"}
			if op == "pull-file" {
				methods = []string{"blob", "discover"}
			}
			for _, method := range methods {
				if counts[method] == 0 {
					continue
				}
				for _, mode := range []string{"context-before", "context-after"} {
					if op == "pull-file" && mode == "context-after" {
						continue // Lost replies are modeled at durable-write boundaries.
					}
					t.Run(method+"-"+mode, func(t *testing.T) {
						shardCase(t)
						exercise(t, 79, Plan{Devices: 3, Probe: &Probe{op, Fault{method, counts[method], mode}}})
					})
				}
			}
		})
	}
}
func TestInvalidActionDeviceIsRejectedBeforeBootstrap(t *testing.T) {
	for _, device := range []int{-1, 2} {
		tape, err := Prepare(1, "", Plan{Devices: 2, Actions: []Action{{Kind: "read", Device: device}}})
		if err != nil {
			t.Fatal(err)
		}
		if err := Execute(context.Background(), tape, t.TempDir()); err == nil {
			t.Fatalf("invalid device accepted: %d", device)
		}
		if len(tape.Recording.Entries) != 1 {
			t.Fatal("invalid plan reached bootstrap")
		}
	}
}
