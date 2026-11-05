# Deterministic simulation

Run `task simulation/test` for complete matrices and exploration. Ordinary
`go test ./...` and coverage keep bounded record/replay regressions; full matrices
require `ENBU_SIM_EXPLORE=1`. `task simulation/smoke` runs three representative
concurrency, crash-recovery, and compound-clock cases. Native `all/test` uses this
bounded smoke target instead of duplicating full exploration in unit and scenario
coverage. The implementation is Go, uses the real application,
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
| `PullSecretsToFile`, `PullSecretsToFileWith` | file-output; dotenv output, preservation of local-only variables, deletion with and without markers, repeat pulls, unreadable historical revisions, and explicit replace; file-pull faults verify the original output remains intact on failure and correct after recovery. |
| `ReadConfig`, `WriteConfig` | file-output, public-surface, local-corruption; protected workspace ID, malformed personal state, cache damage. No transport calls; storage scheduling is inapplicable. |

The catalog test fails when an exported App operation has no driver or inventory
entry. The table describes tested behaviors, not exhaustive proof over all possible
states. Generated sequences and fault exploration supplement the fixed assertions.

`TestOperationStateMatrix` enumerates 21 data/history/membership operations × 4 states
(never written, populated, last key deleted, absent environment) × 4 membership
states (admin, member, pending, removed): 336 named cases. Every case records
and replays, asserts the expected result code, checks the resulting secret map on
all devices and the exact member/admin set, and checks a second environment was unaffected. This matrix covers
these dimensions explicitly; environment presence is inapplicable to Control metadata
and membership operations. `TestConcurrentOperationMatrix` enumerates all ordered
pairs of edit/delete/import/sync, same and different keys, under four seeded
schedules (128 record/replay cases). Conflicts must retain both candidates and
require explicit resolution; disjoint changes must compose. Concurrent additions
also cover same and different keys under four schedules.

`TestMultiUserSwarmMatrix` runs 3–8 devices × eight scenes × four schedules:
192 record/replay cases. All writers reach the publication boundary before any
writer publishes. Scenes cover disjoint additions, mixed disjoint edit/delete/
import/sync, identical edits, identical deletions, distinct edits, edit versus
deletion, conflicting two-key imports, and an offline observer returning after
the other writers finish. Every device must see the exact conflict candidate
sets, including deletions and every writer's distinct value. After resolution
or a clean merge, every device restarts and concurrently adds another unique
key; reverse-order sync must preserve all acknowledged changes on every device.
Unrelated values and each writer's untouched keys are compared with the model.

`TestCompoundMultiUserMatrix` crosses two membership changes (remove a writer
or demote a competing admin), three publication failures (stop before, stop
after, lost reply), three pairs of resolution choices (same value, different
values, value versus deletion), and four schedules: 72 record/replay cases.
Each case starts with an edit/delete conflict and an offline device, forces
the admins to fork Control while the data conflict is unresolved, checks that
the fork blocks resolution, and verifies exact membership after joining the
Control branches. Incomplete data re-encryption must be reported. Two members
then resolve simultaneously while one fails at publication; durable competing
choices must remain an explicit conflict. The fixture resolves again, syncs,
compacts, reconnects the observer, readmits the removed writer when applicable,
and checks both environments and a fresh write. Same-value sibling resolutions
must refuse compaction until sync. The separate production environment must
retain its sentinel throughout, and removal denies access to it too.

`TestConcurrentHistoryRestore` overlaps restoration of an older snapshot with
edit/delete/import/sync/restore and compaction under four schedules: 40 cases.
Same-key conflicts retain both candidates; disjoint changes compose. Compaction
must actually remove a historical revision while the in-flight restore survives.
The membership/write matrix also covers approval and restoration together. When a
returning member cannot decrypt a pre-join merge base, readable heads must agree
or retain their exact differing values as conflicts. An existing member with the
old key syncs them before all devices are checked for convergence.

`TestTeamMembershipWriteMatrix` overlaps six membership changes (approve a
joiner, remove another member, remove the writer, promote another member, demote
the writer, approve the writer's key update) with add/edit/delete/import/sync/restore,
under four schedules: 144 cases. It verifies the member/admin set, preserved
unrelated data, removal denial, no resurrection on readmission, and fresh writes
after readmission. Revocation may set aside a concurrently published old-Control
branch that no remaining member accepted; readmission must not revive it.

`TestConcurrentAdminMatrix` covers ten competing-admin scenes under four
schedules: same/different approvals and removals, promotions, promotion versus
demotion, removal versus promotion/key-update approval, and demotion/removal of
one competing admin. Every fork must block reads and writes, require an admin of
all branches to resolve, and resolve to the membership/admin intersection.
Compound partitions, forks, local file failures and
hardware behavior remain the separately named scenarios and integration tests.

Generated sequences contain a concurrent group every 16 actions. Each group
chooses two distinct devices, edit/delete/import/sync, and same/different keys
from the seed; on workspaces with at least three devices it may also overlap a
third admin's history compaction. Writers reach publication before any writer
commits. The independent merge oracle checks exact conflicts or composition,
preserves the preceding workload's unrelated values, and seals the group before
later sequential actions. Group boundaries and schedules are recorded and replayed.
A three-actor team group every 32 actions additionally overlaps removal, a continuing member's write, and the removed device's synchronization. It retains all preceding workload data and checks denial in every environment, explicit readmission, exact membership, and preservation of the continuing member's acknowledged write. Other membership races remain the explicit team/compound matrices.

Generated sequences mix secret operations with environment create/switch/rename/
delete, compaction, membership remove/rejoin, role changes and restarts. After
every action, all live environments are compared on every device. Rejoining after
a hybrid key update has a dedicated regression case.

`TestThreeWayMergeDAGMatrix` builds real encrypted, signed revisions and checks
659 DAG cases: 64 ordinary three-way merges, 64 unequal branch lengths,
16 unrelated roots, 256 criss-cross merges with two merge bases, 256 three-head
merges, plus late resolution, missing-base recovery and independent simultaneous
key conflicts. The finite value domain distinguishes absence, empty strings,
and two distinct values. Expected outcomes come from enumerating values that
satisfy the merge specification, independently of the merge package and DAG.
The test checks the actual merge bases, exact conflict candidates, explicit value
or deletion resolution, convergence on every device, and parent links of the
published merge revision. Partial and stale resolutions must be refused.
`pkg/merge` additionally enumerates all 64 single-key three-way states with head
reordering/duplication and both choice types; it runs in the DST CI job too.

`TestMultiUserClockProfiles` repeats history, key update, membership,
concurrent disjoint writes, conflicting edits, and Control fork with frozen,
backward-moving, and independently skewed device clocks under four schedules:
72 record/replay cases. This checks that timestamps do not override causal
history or membership authority. These profiles use `Runtime.Clock` with a shared manual timer clock and
per-device wall-clock views. Reading `Now` never advances time; recorded storage
boundaries advance the timer clock by one millisecond. Clock-contract tests verify
repeated reads and exact deadline expiry for every profile. Wall-clock timing never
chooses the scheduler's next actor. Physical file-lock contention remains covered
by the WSP FakeClock regression rather than simulated process scheduling.

`TestClockProfilesWithCompoundRaces` adds 216 record/replay cases: the three clock
profiles crossed with both membership changes, all three publication failures,
all three resolution pairs, and four schedules from the compound fixture. It
checks Control forks, incomplete re-encryption, simultaneous resolutions, recovery,
compaction, offline observers, and readmission with the same independent model.

`TestCompactionLatePublicationAndCrashRecovery` adds 104 record/replay cases:
four late-publication outcomes (valid signed state, invalid junk, temporarily
missing head, temporarily corrupt head) crossed with six deletion outcomes
(success, failure before commit, lost reply, cancellation, crash before commit,
crash after commit) and four schedules. Eight further cases return a terminal transport error or
cancellation while fetching the late head; no deletion may start, the cause
must survive normalization, and recovery must retain the publication.
Publication happens after the compactor's
verified read and before its own listing. Valid or temporarily unreadable objects
must survive; served invalid objects may be deleted. All devices restart before
recovery, including an observer whose checkpoint precedes the compaction floor.
Partially completed deletions must remain readable through signed records, retry
must succeed, and the observer must be able to publish a fresh change.

## Exploration controls

- `ENBU_SIM_EXPLORE=1`: enable complete finite matrices; DST CI and `task simulation/test` set it explicitly.
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

Every generated run is replayed. Pushes select affected suites using
`scripts/dst_plan.py`: secret, history, membership, trust, merge, clock, file and
identity changes map to their related drivers. A changed simulation test file
selects its tests directly. Changes to shared or unknown application/protocol
code conservatively broaden the selection; frontend/provider adapters and docs
without simulation dependencies do not run DST. The planner prints the changed
paths and selected tests in the Actions summary. Push exploration uses two seeds
per lane, 32 actions and representative fault positions.

Full exploration runs daily at **02:00 Asia/Tokyo (17:00 UTC)** and on manual
dispatch. It uses all tests, exhaustive fault positions, and 1,024 seeds × 256
actions per platform, half fixed and half derived from the commit SHA.
Scheduled full runs are not cancelled by incremental pushes.

Both modes use one job each for Linux x64, Linux ARM64, macOS ARM64, Windows x64
and Windows ARM64. Each job uses GitHub Actions `parallel` for four lanes with
logical shards 0–3. Go runs with `-parallel=1`; each lane has separate logs,
recordings and an App coverage profile. Full runs use 256 seeds per lane. The
seed partition test proves this retains the original 1,024 workloads per
platform. Each world keeps its own deterministic scheduler and strict replay.
A timeout is failure. The full job is limited to six hours, with a 330-minute
Go timeout leaving time for mutation checks and artifact upload. Incremental jobs
have a 45-minute limit and a 30-minute Go timeout. Failure artifacts contain
synthetic private keys and plaintext to recreate the fixture; never use real
workspace data.

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
A simulated stop aborts application control flow at a storage boundary and recreates the App from preserved files and synthetic identities. Deferred handle releases still run; interruption within a filesystem syscall and loss of volatile OS buffers are outside this model. Restart reconstructs App, Runtime, and the identity-manager wrapper through the
same explicit factory used at startup. Only durable synthetic key material,
local files, and the external storage/fault harness survive. A regression poisons
old process callbacks and flags, then verifies durable selection, pending keys,
checkpoints and fresh writes survive without reusing them;
separate process replay proves recording independence. Native race tests and E2E
remain required. No claim of enumerating the entire state space is made.

Thirteen isolated mutation experiments check that the oracles detect lost updates,
missed conflicts, unauthorized membership changes, missed rollback, deletion of
a valid late publication, deletion of a temporarily unreachable publication, a wrong observer acceptance
epoch, revival of a revoked author, omitted signature verification, unchecked parent-admin authority, unauthorized compaction records, and unsafe fork resolution.
Every experiment first requires the unmodified behavioral test to pass; compiler
failures do not count as detected bugs.


`TestAcceptanceEpochSurvivesReadmissionAndAuthorRemoval` adds 128 record/replay
cases: acceptance before/after the observer's removal and readmission, a restarted
or continuing observer, member/admin roles, four clock profiles, and four seeds.
The author remains continuously authorized when its old-Control revision is
published. Control transitions deliberately omit automatic re-encryption so that
it cannot mask the checkpoint property. After author removal, only a post-readmission
acceptance may authorize takeover; a pre-removal checkpoint must fall back to
the earlier legitimate parent. Author readmission must not revive a rejected
branch. Fresh writes, compaction, restart, and a second environment are checked.
Two bounded smoke cases run in ordinary CI too.

The `forged-state-signature` scenario keeps valid canonical state bytes and matching
ciphertext while flipping a signature bit, signing with a different device,
signing under the wrong protocol domain, or truncating the signature. Every
member must reject the injected value after restart, and subsequent valid writes
and compaction must preserve the independent model. Parser-invalid junk alone
would not establish that the cryptographic signature is actually checked.


`TestAuthorityAttackMatrix` crosses seven canonical, correctly signed attacks
with four clock profiles and four seeds: 112 record/replay cases. Ordinary members
try to promote themselves and remove the founder, demoted admins try to regain
admin rights, and removed admins try to reinsert themselves. A member-signed
compaction record must not excuse deletion of an acknowledged head. A genuine
admin's fork resolution must not introduce a new admin or swap a recipient.
Every attack checks exact membership, fail-closed access where applicable, a
second environment, restart, legitimate subsequent writes, and compaction.
`TestAuthorityAttackSmoke` runs all seven attacks in ordinary CI. Three isolated
mutations disable the corresponding protocol checks and must fail their specific
behavioral assertions, rather than merely fail compilation.

`locked-device` models a temporarily unavailable key store: initialization,
reading, editing, pulling, and synchronization must fail with the actionable
identity error; the local dotenv file must remain byte-for-byte intact. Another
developer can update the workspace while the device is locked. Unlock/restart
must preserve those updates and permit fresh writes without publishing local-only
variables. `rejected-edits` checks negative, zero, and out-of-range history
indexes, plus rejected workspace/genesis/incarnation edits leaving the original
configuration unchanged. The state matrix additionally crosses stale-head
resolution, missing-head resolution, and file pull with every data/member state.

The team incident journey runs 96 combinations of 3–8 devices, four clock
profiles, and four seeds. It follows release conflicts, explicit resolution,
employee departure, retained-key attacks, cross-environment replay, compaction,
and explicit readmission. The migration journey checks offline checkouts across
environment renaming and reuse of the old name, preservation of work and local
variables, configuration refresh, and restart after compaction.


`request-signature-attack` publishes canonical join requests with a flipped
signature, a different signing key, a different protocol domain, or another
workspace. None may become approvable. A valid request must remain identifiable
among the injected objects and must not grant membership until an admin approves.
The corresponding mutation disables request signature verification and must be
detected by this scenario.


`TestGeneratedTeamGroupsPreservePriorWork` checks 24 seeded generated workloads
across 3–8 devices with the mixed membership/write/sync group. A bounded smoke
case runs in ordinary CI; full generated exploration includes these groups too.
