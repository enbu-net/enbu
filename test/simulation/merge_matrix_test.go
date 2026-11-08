package simulation

import (
	"fmt"
	"testing"
)

func TestThreeWayMergeDAGMatrix(t *testing.T) {
	exploration(t)
	index := 0
	run := func(c MergeCase) {
		index++
		if !ownsIndex(t, index-1) {
			return
		}
		c.DeleteChoice = index%2 == 0
		t.Run(fmt.Sprintf("%s/base-%d-%d/heads-%v", c.Shape, c.Base, c.OtherBase, c.Heads), func(t *testing.T) { exercise(t, uint64(index), Plan{Devices: 4, MergeCase: &c}) })
	}
	for _, shape := range []string{"normal", "unequal"} {
		for b := 0; b < 4; b++ {
			for l := 0; l < 4; l++ {
				for r := 0; r < 4; r++ {
					run(MergeCase{Shape: shape, Base: b, Heads: []int{l, r}})
				}
			}
		}
	}
	for l := 0; l < 4; l++ {
		for r := 0; r < 4; r++ {
			run(MergeCase{Shape: "no-base", Heads: []int{l, r}})
		}
	}
	for b := 0; b < 4; b++ {
		for other := 0; other < 4; other++ {
			for l := 0; l < 4; l++ {
				for r := 0; r < 4; r++ {
					run(MergeCase{Shape: "criss-cross", Base: b, OtherBase: other, Heads: []int{l, r}})
				}
			}
		}
	}
	for b := 0; b < 4; b++ {
		for l := 0; l < 4; l++ {
			for m := 0; m < 4; m++ {
				for r := 0; r < 4; r++ {
					run(MergeCase{Shape: "three-heads", Base: b, Heads: []int{l, m, r}})
				}
			}
		}
	}
	run(MergeCase{Shape: "late-resolution", Base: 2, Heads: []int{3, 1}})
	run(MergeCase{Shape: "missing-base", Base: 2, Heads: []int{3, 1}})
	run(MergeCase{Shape: "two-keys", Heads: []int{2, 3}})
}
