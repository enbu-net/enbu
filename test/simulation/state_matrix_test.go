package simulation

import (
	"os"
	"strconv"
	"testing"
)

func TestOperationStateMatrix(t *testing.T) {
	for index, op := range StateOperations {
		shards := integer(t, "ENBU_SIM_SHARDS", 1)
		shard := 0
		if shards > 1 {
			var err error
			shard, err = strconv.Atoi(os.Getenv("ENBU_SIM_SHARD"))
			if err != nil || shard < 0 || shard >= shards {
				t.Fatal("invalid shard")
			}
		}
		if index%shards != shard {
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
