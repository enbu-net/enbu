# Implementation-refinement models

The authoritative protocol models are the five models in
[`../tla/`](../tla/README.md), brought in from `test/formal-tla`.
These smaller models are executable test oracles for the Go implementation:
`internal/tla` runs TLC, reads the state dump, and the conformance tests rebuild
the inputs using real signing keys and compare the decisions with Go.
They are not a replacement for the protocol specification.

- `ControlDAG` enumerates signed Control stores, including forged signatures
  and a compromised admin. `TestControlVerifierMatchesTheModel` compares
  verified objects and heads with `wsp.LoadControl`.
- `StateDAG` records each read's input, checkpoint and expected output.
  `TestReaderMatchesTheModel` compares these with the application's reader.
  The default oracle asserts the stronger rollback protection; `count-proven`
  describes the pre-F2b implementation and exhibits its removed-key
  rollback finding. A failure against the stronger oracle must not be hidden
  by selecting `count-proven` in required CI.
- `MemberChange` checks more finely interleaved writes during removal and
  approval. `Founding` checks atomic trust-pin transitions, including an
  explicitly confirmed replacement root.

`checks.toml` lists the expected results for these refinement models, seeded
bugs and reachability witnesses. `task formal/refinement` runs them and checks
action coverage. `task formal/conformance` compares the reader and verifier
with their dumps. Tests and properties are linked in
[`../IMPLEMENTATION_INVARIANTS.md`](../IMPLEMENTATION_INVARIANTS.md).
The refinement table's IDs are a separate namespace from protocol IDs in
`../INVARIANTS.md`; identically numbered IDs need not mean the same property.

Known counterexamples from the protocol models remain under `../tla/traces`.
In particular, `StateDAG_finding_removed_sibling` and the refinement finding
F2b describe the same weakness, now fixed by trusting only current heads as
freshness evidence and retained as seeded regressions. The Go regression is
`TestRemovedKeyCannotMaskARollback`.
