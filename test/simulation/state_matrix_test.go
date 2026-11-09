package simulation

import (
	"testing"
)

func TestOperationStateMatrix(t *testing.T) {
	exploration(t)
	for index, op := range StateOperations {
		if !ownsIndex(t, index) {
			continue
		}
		for _, state := range DataStates {
			for _, role := range MemberStates {
				t.Run(op+"/"+state+"/"+role, func(t *testing.T) {
					exercise(t, 701, Plan{Devices: 3, StateCase: &StateCase{Operation: op, State: state, Role: role}})
				})
			}
		}
	}
}
