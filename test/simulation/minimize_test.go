package simulation

import "testing"

func TestMinimizePreservesFailingOperation(t *testing.T) {
	t.Parallel()
	actions := []Action{{Kind: "read"}, {Kind: "add", Key: "BUG"}, {Kind: "sync"}, {Kind: "history"}}
	result := Minimize(actions, func(candidate []Action) bool {
		for _, op := range candidate {
			if op.Key == "BUG" {
				return true
			}
		}
		return false
	})
	if len(result) != 1 || result[0].Key != "BUG" {
		t.Fatalf("not minimal: %v", result)
	}
	if got := Minimize(actions, func([]Action) bool { return true }); len(got) != 0 {
		t.Fatalf("irrelevant actions retained: %v", got)
	}
}
