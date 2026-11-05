# Deterministic simulation

Run `task simulation/test`. The implementation is Go, uses the real application,
age encryption/decryption, signed protocol and merge, and needs no cloud credentials,
Docker, frontend build or OS keyring. Every identity and value is synthetic.

## Reproduction

A seed defines the workload and scheduling choices. Exact replay additionally
requires the recording and the matching code revision, because real crypto creates
random ciphertext. Crypto inputs are checked and recorded outputs reused; decryption
and verification run normally. Global crypto randomness is never replaced.

`ENBU_SIM_REPLAY=/absolute/recording.json go test -count=1 ./test/simulation -run '^TestReplay$'`

The tape rejects different inputs, outputs, kinds, missing calls and extra calls.
`TestReplayAcrossProcesses` replays with fresh paths in three new processes.
The scheduler permits one actor to run between external boundaries; internal
speculative head reads are explicitly made sequential for this context. Ordinary
production head prefetch remains parallel.

## Operation coverage

| Application operations | Scenarios, rejection, concurrency, faults and recovery |
| --- | --- |
| `InitializeRepository` | Bootstrap, founding faults at every external-call occurrence, lost-reply and digest-mismatch tests; founder and joiner paths; retry exact signed Control. |
| `CreateIdentity`, `IdentityInfo`, `DiagnoseIdentity`, `LoadWorkspaceIdentities` | public-surface; synthetic software identities. OS/hardware failure and diagnostic detail stay in identity E2E. |
| `DefaultStorageURL`, `SetRepositoryDir`, `WorkspaceID` | public-surface; fixture repository; shared workspace identifiers and per-device paths. |
| `ListSecrets`, `AddSecret`, `EditSecret`, `DeleteSecret`, `ImportSecrets`, `SyncSecrets`, `PullSecretsData`, `PullSecrets` | Generated independent reference model; duplicate/missing keys, overwrite, invalid operations; concurrent-keys, stale-writer, write/read-faults; operation fault matrix. |
| `ListConflicts`, `ResolveSecrets` | conflicting-edits; same-key edits stop reads, stale resolution rejected, explicit resolution converges. Existing app conflict tests cover edit/delete and criss-cross merges. |
| `ListMembers`, `ListJoinRequests`, `ApproveMember`, `RemoveMember`, `SetAdmin`, `ResolveControlFork` | membership, control-fork, adversarial-storage; member/admin authorization; fork blocks reads; intersection resolution; pending requests and removal/rejoin; operation fault matrix. |
| `UpgradeIdentity` | key-update; member approval and direct admin upgrade, real hybrid encryption; operation fault matrix and retry after interrupted approval. |
| `ListEnvironments`, `CurrentEnvironment`, `SwitchEnvironment`, `SwitchPrevious`, `CreateEnvironment`, `DeleteEnvironment`, `RenameEnvironment` | environments, public-surface, local-corruption; personal selections do not leak, rename retains incarnation, recreation starts empty, invalid names and current-environment deletion rejected. These configuration operations have no storage calls; transport faults are inapplicable. |
| `DeleteEnvironmentPurging`, `PurgeIncarnation` | environments, purge operation fault matrix; orphan incarnation reclamation and restartable partial deletion; only admin may delete. |
| `ListHistory`, `DiffHistory`, `RestoreHistory`, `CompactHistory` | history, delete-faults; expected diff and restored state; compaction preserves current content and checkpoints; faults at every observed external call. Existing compaction scenarios cover old offline branches and repeated records. |
| `PullSecretsToFile`, `PullSecretsToFileWith` | file-output; dotenv output and explicit replace after unreadable file; storage faults covered by pull probe. |
| `ReadConfig`, `WriteConfig` | file-output, public-surface, local-corruption; protected workspace ID, malformed personal state, cache damage. No transport calls; storage scheduling is inapplicable. |

The catalog test fails when an exported App operation has no driver or inventory
entry. The table describes tested behaviors, not exhaustive proof over all possible
states. Generated sequences and fault exploration supplement the fixed assertions.

## Exploration controls

- `ENBU_SIM_SEEDS`, `ENBU_SIM_STEPS`: generated sequences per shard and sequence length.
- `ENBU_SIM_SHARDS`, `ENBU_SIM_SHARD`: reproducible disjoint seed ranges and operation fault matrices.
- `ENBU_SIM_EXHAUSTIVE=1`: inject at every observed external-call occurrence;
  otherwise test first and last occurrence for each method.
- `ENBU_SIM_ARTIFACTS`: recording output directory; failed runs are always saved.
- `ENBU_SIM_SAVE_ALL=1`: also retain passing runs.

Founding has its own full boundary matrix, including verification after publication. Recovery bytes remain until trust acceptance succeeds. The operation fault matrix first measures each operation's actual external calls,
then injects network failure, cancellation and simulated device stops at each selected position, plus lost
responses after publish/delete. Before recovery, state must equal either the old
or intended committed state. An acknowledged operation must have its intended
result. Recovery retries only effects not already committed, then verifies all
members against the independent model. Temporary failures do not authorize losing
unrelated values. Persistent partitions, stale writers, truncated reads, corruption,
missing objects and invalid signed objects have separate scenarios.

Every generated run is replayed. CI runs once per branch push, and supports manual dispatch, on Linux x64, Linux ARM64, macOS ARM64 and Windows x64. Each platform uses eight
shards, each exploring 128 seeds × 256 actions (half fixed, half derived from the commit SHA), plus fixed and exhaustive fault
cases. A timeout is failure. Failure artifacts contain synthetic private keys and
plaintext so they can recreate the exact fixture; never use real workspace data.
Oracle failures in long operation sequences are reduced by chunk deletion, and a
reduced case is kept only when a fresh recording reproduces the same property
failure and strict replay reproduces it again. Original recordings are retained. An append-only `.journal` also preserves the executed prefix if a process timeout prevents normal cleanup.

## Complementary integration evidence

Simulation tests the application contract, not native UI events or a registry's
HTTP implementation. `test/scenario_test.go`, `test/e2e/`, desktop/RPC tests,
web frontend tests and VS Code tests cover their adapters. `test/identitye2e/`
covers real key stores and TPM fixtures; `pkg/storage/remote_e2e_test.go` and storage
E2E cover OCI/S3. OAuth, shell execution, completion and editor trust handling stay
in those suites. The in-memory fault store itself runs the shared storage contract.

Physical filesystem/power-loss durability, external provider behavior, hardware
failures and arbitrary Go data races are not modeled by the virtual scheduler.
A simulated stop aborts application control flow at a storage boundary and recreates the App from preserved files and synthetic identities. Deferred handle releases still run; interruption within a filesystem syscall and loss of volatile OS buffers are outside this model. Restart scenarios preserve files and identities while replacing App instances;
separate process replay proves recording independence. Native race tests and E2E
remain required. No claim of enumerating the entire state space is made.
