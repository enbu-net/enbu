# TLA+ models

Five models of enbu's protocol, checked with TLC ([tlc-static](https://github.com/yashikota/tlc-static), installed by aqua).
The properties they check are listed with their IDs in [../INVARIANTS.md](../INVARIANTS.md).
The executable Go tests are linked in that table. Additional implementation-refinement models, used to compare real signed inputs with TLC's decisions, live separately under [../conformance/](../conformance/README.md).

```sh
task formal/check                       # small configs, mutants, examples and findings
task formal/model MODEL=StateDAG        # one model
task formal/check/large                 # large configs (minutes; nightly)
task formal/traces                      # rewrite traces/ from the configs naming a trace file
```

Each model lives in its own directory as `<Model>.tla` with these configs:

- `<Model>.cfg`: the small config, run in CI. Every property must hold.
- `<Model>.large.cfg`: the same properties over a larger state space.
- `<Model>_<bug>.cfg`: a mutant. The constant `Bug` switches one rule of the model to a defect, pre-fix behaviour included, and the config's `\* expect: violation P` line names the property TLC must then report violated.
- `<Model>_example_*.cfg` and `<Model>_finding_*.cfg`: the implementation itself (`Bug = "none"`), with a property TLC is expected to violate: a limit the design accepts, or an open finding.

`scripts/formal.py` runs every config and fails when a config does not end as it expects.

## Models

| Model | What it covers | Small config (12 cores) |
|-------|----------------|-------------------------|
| ControlDAG | The signed Control DAG: `VerifyGenesis`/`VerifyChild`/`checkResolution`, `LoadControl` with the checkpoint, `openControl`'s automatic fork resolution. Honest admins change members from possibly stale sessions; a malicious admin forks and resolves with the union; a member and an outsider forge; storage hides and replays. | 15k states, 4 s |
| StateDAG | One environment's revision DAG: `VerifyRevision`, `dropWrongGenerations`, `trustedHeads`, `shownGeneration`, the Generation checkpoint, `MaxGeneration`, compaction (`--keep 1`) and a removal in two steps. A removed member signs with its old key; storage hides and replays. | 46k states, 11 s |
| MemberChange | `RemoveMember` (re-encrypt without the member, then publish the Control on the view it re-encrypted under), `ApproveMember` (publish, then re-encrypt), concurrent writes with both `controlUnchanged` checks, forks and their resolution. Storage errors fail re-encryption. | 39k states, 2 s |
| WriteRetry | `changeResource`: read, look again, check the Control before and after publishing, the retry bound, `published` / `publishedInRead`, a lagging listing. | 163k states, 10 s |
| Founding | `enbu init` founding a workspace: `FindGenesis`, publish (lost replies), `enbu.toml`, `trust.json` pins (`PinFirst`, `PinFounded`), crashes at every step, an attacker writing storage and the repository. | 186k states, 3 s |

## Mutants

| Config | Defect | Violates |
|--------|--------|----------|
| `ControlDAG_no_admin_check` | `VerifyChild` accepts any author | AUTH_1 |
| `ControlDAG_admin_any_parent` | the author need be an admin of one parent only | AUTH_1 |
| `ControlDAG_no_sig_check` | the signature is not checked against the author's key | AUTH_2 |
| `ControlDAG_F4` | pre-fix F4: a resolution may keep any subset of the union | FORK_1 |
| `ControlDAG_no_checkpoint` | accepted Control heads are not required in the view | CP_1 |
| `ControlDAG_proceed_on_fork` | a device that cannot join a fork proceeds on one head | FORK_2 |
| `ControlDAG_no_auto_resolve` | an admin of every head reports the fork instead of joining it | FORK_3 |
| `StateDAG_F1` | pre-fix F1: a State naming an unknown Control is a rollback | GEN_2 |
| `StateDAG_F2` | pre-fix F2: every verified revision counts towards the rollback check | GEN_1 |
| `StateDAG_F3` | pre-fix F3: no Generation bound, a child of the largest wraps | GEN_4 |
| `StateDAG_skip_gen_check` | `dropWrongGenerations` skipped | GEN_5 |
| `StateDAG_no_checkpoint` | the checkpoint is not compared with the view | GEN_1 |
| `StateDAG_lower_checkpoint` | `AcceptState` may lower the checkpoint | GEN_3 |
| `StateDAG_no_rejoin_check` | `AuthorIsCurrent` checks only the current Control | REJOIN_1 |
| `MemberChange_reverse_removal_order` | publish the Control, then re-encrypt | RCPT_3 |
| `MemberChange_no_control_check` | `writeState` skips `controlUnchanged` | RCPT_2 |
| `MemberChange_removal_includes_member` | the removal re-encrypts for the member it removes | RCPT_4 |
| `MemberChange_approve_no_reencrypt` | approval does not re-encrypt | APPROVE_1 |
| `MemberChange_resolve_no_reencrypt` | joining a fork does not re-encrypt | RESOLVE_1 |
| `WriteRetry_no_published_tracking` | a retry forgets what it published | SYNC_2 |
| `WriteRetry_no_also` | a retry does not pass its revisions to a lagging listing | SYNC_2 |
| `WriteRetry_merge_latest_heads` | publish on the newest heads with stale content | SYNC_1 |
| `WriteRetry_unbounded` | no retry bound | SYNC_3 |
| `WriteRetry_F5` | pre-fix F5: exhausted retries are an internal error | SYNC_4 |
| `Founding_adopt_any_genesis` | `FindGenesis` ignores the author | TRUST_2 |
| `Founding_founded_by_storage` | any genesis enbu.toml names counts as founded here | TRUST_2 |
| `Founding_toml_before_publish` | enbu.toml names the genesis before it is published | TRUST_3 |
| `Founding_no_find_genesis` | a retry does not look for its own genesis | TRUST_4 |
| `Founding_founding_repins` | a pinned device founds again and re-pins | TRUST_1 |
| `Founding_no_repo_pin` | the repository pin is not checked | TRUST_5 |

`StateDAG_finding_removed_sibling` is now a fixed-regression mutant (`Bug = "F2b"`),
not an open finding: complete ancestry does not give a removed key freshness
authority. Base configurations require `GEN_1_strict`. Removal-race availability
findings remain; the fix fails closed rather than returning old secrets.

The counterexamples of the pre-fix mutants (F1–F5) and of the examples and findings are kept in [traces/](traces/).

## Abstractions

- Digests are indices into the sequence of signed objects (Founding: the record itself). A signature is a `signer` field; nobody signs as someone else.
- ControlDAG: an admin's open and the resolution it publishes are one step, so two admins never join the same fork at once (the implementation retries `forkRetries` times; a livelock is possible in principle). `acceptControlHead` after an update is left to the next open, which only delays a checkpoint. Keys appear only as Member's key on rejoin.
- StateDAG: the Control is the fixed chain C1 (M listed) → C2 (M removed) → C3 (M approved again, same key). Content is not modelled; Generation, authorship and presence are. A removal re-encrypts every trusted head in one step, then publishes the Control. Compaction keeps one revision. `RemovalRace = FALSE` keeps M from writing between the two steps of its removal; the findings set it.
- MemberChange: content is who a revision is encrypted for. Every member is honest; R1 and R2 are admins wherever they are members. A removal's re-encryption, an approval's re-encryption, and a fork resolution with its re-encryption are each one step. One environment.
- WriteRetry: storage is honest; content is a set of keys merged by union. The Control is a version number.
- Founding: one founding device and one attacker; `--accept-new-genesis` is not modelled. The attacker can write storage and enbu.toml but cannot sign as the device.
