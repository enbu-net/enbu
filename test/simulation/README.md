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

Named clock/device journeys and the scenario catalog use a stable test-name hash to assign one Actions lane per case. Previously these newer matrices repeated on all four lanes, and both Windows targets hit the 30-minute test timeout. A local unpartitioned-versus-four-lane audit retained the same 437 passing named cases, assigned 110/108/113/106, with no omissions or duplicates. Existing index-partitioned matrices and the 1,024-seed partition remain unchanged. Native dependency `_test.go` changes run in normal CI without repeating DST; implementation changes retain their affected-domain rules, and changes to shared simulation test helpers widen selection to all matrices.

## Operation coverage

| Application operations | Scenarios, rejection, concurrency, faults and recovery |
| --- | --- |
| `InitializeRepository` | Bootstrap, founding faults at every external-call occurrence and lost-reply tests; founder and joiner paths; `enbu.toml` names a genesis only after its publish returned, and a retry adopts the genesis this device signed instead of publishing another. |
| `CreateIdentity`, `IdentityInfo`, `DiagnoseIdentity`, `Diagnose` | public-surface; synthetic software identities. Healthy workspace diagnosis must succeed without storage writes and replay its report; OS/hardware failure stays in identity E2E. |
| `DefaultStorageURL`, `SetRepositoryDir`, `WorkspaceID` | public-surface; fixture repository; shared workspace identifiers and per-device paths. |
| `ListSecrets`, `AddSecret`, `EditSecret`, `DeleteSecret`, `ImportSecrets`, `SyncSecrets`, `PullSecretsData`, `PullSecrets` | Generated independent reference model; duplicate/missing keys, overwrite, invalid operations; concurrent-keys, stale-writer, write/read-faults; operation fault matrix. |
| `ListConflicts`, `ResolveSecrets` | conflicting-edits; same-key edits stop reads, stale resolution rejected, explicit resolution converges. Existing app conflict tests cover edit/delete and criss-cross merges. |
| `ListMembers`, `ListJoinRequests`, `ApproveMember`, `RemoveMember`, `SetAdmin` | membership, control-fork, adversarial-storage; member/admin authorization; fork blocks reads of devices that are not an admin of every head; the next operation of an admin of every head joins it to the intersection (ADR-25); pending requests and removal/rejoin; operation fault matrix. |
| `ListEnvironments`, `CurrentEnvironment`, `SwitchEnvironment`, `SwitchPrevious`, `CreateEnvironment`, `DeleteEnvironment`, `RenameEnvironment` | environments, public-surface, local-corruption; personal selections do not leak, rename retains incarnation, recreation starts empty, invalid names and current-environment deletion rejected. These configuration operations have no storage calls; transport faults are inapplicable. |
| `DeleteEnvironmentPurging`, `PurgeIncarnation` | environments, purge operation fault matrix; orphan incarnation reclamation and restartable partial deletion; only admin may delete. |
| `ListHistory`, `DiffHistory`, `RestoreHistory`, `CompactHistory` | history, delete-faults; expected diff and restored state; compaction preserves current content and checkpoints; faults at every observed external call. Existing compaction scenarios cover old offline branches and repeated compactions. |
| `PullSecretsToFile`, `PullSecretsToFileWith` | file-output; dotenv output, preservation of local-only variables, deletion with and without markers, repeat pulls, unreadable historical revisions, and explicit replace; file-pull faults verify the original output remains intact on failure and correct after recovery. |
| `ReadConfig`, `WriteConfig` | file-output, public-surface, local-corruption; protected workspace ID, malformed personal state, cache damage. No transport calls; storage scheduling is inapplicable. |

The catalog test fails when an exported App operation has no driver or inventory
entry. The table describes tested behaviors, not exhaustive proof over all possible
states. Generated sequences and fault exploration supplement the fixed assertions.

`TestOperationStateMatrix` enumerates 22 data/history/membership operations × 4 states
(never written, populated, last key deleted, absent environment) × 4 membership
states (admin, member, pending, removed): 352 named cases. Every case records
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
the fork blocks every device that is not an admin of both branches, and verifies
exact membership after the remaining admin's next operation joins the Control
branches. Incomplete data re-encryption must be reported. Two members
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
demotion, removal versus promotion, and demotion/removal of
one competing admin. Every fork must block reads and writes of every device that is not an admin of
all branches, and an admin of all branches' next ordinary operation must join it
to the membership/admin intersection.
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
Partially completed deletions must remain readable without any record (deletion
runs oldest first, so no old revision is left looking like a head), retry must
succeed, and the observer must be able to publish a fresh change.

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
per lane, 32 actions and representative fault positions. Finite matrices execute one deterministic eighth of their named cases, selected by the commit SHA; scenario smoke cases and generated seed workloads are never sampled. The upper hash bits select samples independently of lane assignment. Daily/manual full mode and mutation controls force stride 1, so every finite case remains enabled there.

Full exploration runs daily at **02:00 Asia/Tokyo (17:00 UTC)** and on manual
dispatch. It uses all tests, exhaustive fault positions, and 1,024 seeds × 256
actions per platform, half fixed and half derived from the commit SHA.
Scheduled full runs are not cancelled by incremental pushes.

Both modes cover Linux x64, Linux ARM64, macOS ARM64, Windows x64 and Windows
ARM64. Each job uses GitHub Actions `parallel` for four lanes. Incremental mode
runs one job per platform with logical shards 0–3; full mode runs eight jobs per
platform (see Full-run scheduling). Go runs with `-parallel=1`; each lane has
separate logs, recordings and an App coverage profile. The seed partition test
proves the full partition retains the original 1,024 workloads per platform.
Each world keeps its own deterministic scheduler and strict replay. A timeout is
failure. The full job is limited to six hours, with a 330-minute Go timeout
leaving time for mutation checks and artifact upload. Incremental jobs have an
80-minute limit and a 55-minute Go timeout. Failure artifacts contain
synthetic private keys and plaintext to recreate the fixture; never use real
workspace data.

Oracle failures in long operation sequences are reduced by chunk deletion, and a
reduced case is kept only when a fresh recording reproduces the same property
failure and strict replay reproduces it again. Original recordings are retained. An append-only `.journal` preserves the executed prefix if a process timeout prevents normal cleanup. `task simulation/test` sets `ENBU_SIM_ARTIFACTS` to `.tmp/simulation`; set that variable explicitly for direct `go test` runs to enable journaling, or choose another artifact directory. Without it, a timeout cannot retain the prefix.

## Complementary integration evidence

Simulation tests the application contract, not native UI events or a registry's
HTTP implementation. `test/scenario_test.go`, desktop/RPC tests,
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

Thirty-three isolated mutation experiments check that the oracles detect lost updates,
missed conflicts, unauthorized membership changes, missed rollback, a view below the
accepted generation, deletion of a valid late publication, deletion of a temporarily
unreachable publication, revival of a revoked author, omitted signature verification,
unchecked parent-admin authority, and unsafe fork resolution.
Each Actions lane runs its assigned mutation experiments after exploration, with a 15-minute mutation timeout. Experiments are assigned exactly once across the four lanes. Every experiment resets exploration sharding and sampling for its unmodified control and mutant, so both execute the complete intended scenario; compiler failures do not count as detected bugs. Child test processes have a five-minute deadlock guard and are cancelled with the parent test. Control and mutant recordings are retained separately under `ENBU_SIM_ARTIFACTS/mutations/<experiment>/<phase>` (or the system temporary failure directory), outside the disposable source copy. A subprocess regression checks that deleting that source copy preserves the recordings.


`TestAcceptanceEpochSurvivesReadmissionAndAuthorRemoval` adds 128 record/replay
cases: reading before/after the observer's removal and readmission, a restarted
or continuing observer, member/admin roles, four clock profiles, and four seeds.
The author remains continuously authorized when its old-Control revision is
published. Control transitions deliberately omit the re-encryption a removal
publishes first, so that it cannot mask the trust rule. After the author's
removal every observer, whenever it read the author's head, must fall back to
the earlier legitimate parent without seeing a rollback (ADR-26 has no
acceptance exception). Author readmission must not revive the set-aside branch.
Fresh writes, compaction, restart, and a second environment are checked.
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
admin rights, and removed admins try to reinsert themselves. A genuine
member-signed branch of a lower generation must not make storage hiding an
acknowledged head acceptable. A genuine
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

`testdata/nightly-regressions.json` retains 51 unique minimized plans from all
five platforms' artifacts in full run 42316127227. It contains seeds and
operations, not private keys or recorded application results.
`TestGeneratedTeamGroupNightlyRegressions` checks these plans against the model
and then strictly replays fresh recordings. Ordinary CI retains representative
seeds 256 and 440; DST selection includes the corpus when the workload or corpus
changes. With the former generated-team helper, seed 256 again fails with a
secret conflict; the corrected helper seals each continuing observer's ancestry.
The full run reached its 330-minute limit after multiple failures and long
minimizations. Local verification also re-executes and strictly replays all 52
distinct original 256-operation plans retained by that run, including the plans
active when its timeout fired. Both the 51 unique minimized plans with race
detection and all 52 original plans pass. This does not establish that the full
nightly configuration now passes; a new full run is still required. CI lanes
stop after recording and minimizing their first failure; successful runs retain
the complete configured search.

The larger-team matrix partitions its ordered cases by lane and sample phase.
Its actor-count blocks remain balanced across lanes, including incremental
samples, while full mode still executes all 252 worlds. Name hashing formerly
clustered 18 worlds on one lane and only four on another at commit 03f29f6;
Windows timed out while processing the overloaded lane. Partition tests verify
coverage and per-actor-count balance and prevent a second name-based sampling
pass from silently discarding index-selected cases.


`refounding` replaces a lost workspace with a genuinely different signed root
and founder. Sharing the new configuration must block all previously pinned
devices. A failed explicit root acceptance must leave old trust and accepted data
usable. Each device independently confirms the new root; former admins still
need approval and receive ordinary membership, never inherited admin rights.
Reverting shared configuration to the old root must be rejected. New-root admin
delegation and fresh writes restore normal teamwork. The state matrix also
checks reinitialization in all 16 data/member states without identity replacement
or implicit approval.


## Team use-case verification map

Use-case coverage is tracked separately from statement coverage. The following
finite inventory names executable tests and the properties they check. It is a
tested subset, not a complete product inventory; the gap register below blocks
any claim of 100% product use-case coverage. All rows
must pass; a successful API call without its behavioral assertions is insufficient.

| Team workflow | Normal operation and collaboration | Failure, attack, and recovery evidence |
| --- | --- | --- |
| Found or join a workspace | Bootstrap; pending membership; explicit approval; reinitialization across all four member/data states | `TestFoundingEveryStorageBoundaryRecovers`; `request-signature-attack`; no implicit membership or regenerated root on retry |
| Daily secret read/add/edit/delete/import/sync/pull | `TestOperationStateMatrix`; concurrent operation pairs; 3–8-device swarm; generated workloads | Operation boundary faults; locked device; unchanged local files on failed pull; strict independent secret model |
| Resolve concurrent work | `TestThreeWayMergeDAGMatrix`; partial/stale resolution rejection; exact edit/delete candidates | Compound Control/data forks; simultaneous competing resolutions and publication failures; explicit re-resolution and convergence |
| Add/remove/promote/demote teammates | Membership/write matrix; competing-admin matrix; generated three-actor team groups | Signed authority attacks; re-encryption after removal; removed authors/observers across readmission; exact member/admin oracle |
| Move a device key | Remove-and-rejoin journeys; post-quantum recipient sets | Unavailable key store; no stale-key resurrection; explicit unlock/readmission recovery |
| Work offline and catch up | Partition recovery; stale writers; returning swarm observer; migration journey | Rename and reuse an environment name without mixing incarnations; preserved earlier work and local-only dotenv values |
| Maintain multiple environments | Create/switch/previous/rename/delete/recreate; concurrent environment creation | Membership change covers storage scopes absent from an admin's config; protected config edits; unrelated environment sentinel |
| Restore, compact, or purge history | Historical diffs and restore races; compaction; environment purge | Late publications, terminal fetch failures, interrupted deletion; offline checkpoints and restart |
| Defend against untrusted registry objects | Canonical signature and authority attack fixtures | Foreign resource/workspace, wrong signer/domain, malformed signatures, invalid authority, rollback; valid work resumes afterward |
| Recover a deliberately re-founded workspace | `refounding`; `TestRefoundingClockMatrix` plus subsequent generated work | Each device explicitly confirms the new root; failed confirmation preserves old trust; no inherited admin rights; old-root rollback denied |

Transport interleavings apply to storage-backed operations. Pure local selection
and configuration changes instead assert file contents, protected fields, and
per-device selection; transport faults cannot occur inside those operations.
Native key-store/hardware, OAuth, shell execution, and GUI/editor event handling
remain the complementary integration suites listed above, not simulated hardware.
This inventory is finite and reviewable; it does not assert that every unbounded
operation sequence or every future use case has been enumerated.


`first-member` begins before all-member bootstrap: a solo founder maintains
three environments and multiple historical revisions, then genuinely new devices
join for the first time. Before approval, read and file pull must fail and leave
local-only variables intact. Approval must re-encrypt all current environments;
newcomers may collaborate immediately but their keys cannot decrypt retained
pre-join ciphertext. `TestFirstMemberOnboardingClocks` repeats this journey with
2, 3, and 8 devices under four clock profiles (12 record/replay cases).


`secret-formats` shares empty values, multiline certificate/key fixtures, JSON,
Unicode, leading/trailing whitespace, CRLF, quotes/backslashes, comment/equal
characters, and literal shell/variable-expansion syntax. Every device must see
identical plaintext and round-trip dotenv bytes and files without interpreting
those values. Local-only values remain local; sync, compaction, and restart must
retain every exact value.


## Additional workflows and known gaps

`same-user-processes` uses fresh App/Runtime/key-store wrappers and independent
storage actors for the same device identity. Both processes share checkpoints,
caches, and personal selection. It covers one checkout and two checkouts, each
with concurrent disjoint edits, edit/delete conflict, restore/import conflict,
and edit/compaction. The genuine second teammate must observe the result after
its actor slot is restored. Four clock profiles and four schedules exercise 128
operation groups with strict replay. This models App interleavings, not arbitrary
filesystem syscall scheduling or actual GUI/RPC process lifetimes.

`lost-device-replacement` replaces private keys while retaining a checkout backup.
The replacement must have a new device ID, remain unapproved until explicitly
accepted, and never inherit admin authority. A lost laptop retains its old keys:
it can decrypt old ciphertext but not rotated current data. Genuine signatures
from that retired device must not revive its old branch. A new-device write,
compaction, and restart must preserve both environments. Twelve combinations of
2/3/8 devices and four clock profiles exercise this journey.

The original ten broad workflow areas do not exhaust enbu. The following
independent dimensions are missing or only partly verified in DST. Existing
native/unit coverage is not counted as deterministic team-workflow coverage.

| Area | Current evidence and remaining gap |
| --- | --- |
| Same person using multiple clients/processes | New shared-identity App interleavings; actual CLI/GUI/RPC/extension concurrency and filesystem scheduling remain partial. |
| Multiple workspaces under one user | Two workspaces share a user identity namespace, checkpoints, cache and personal state: simultaneous writes, independent environment selection, isolated removal/admin change, restart, foreign-config rejection, bidirectional signed-state relocation attacks, join-request isolation and compaction preserving neighboring revisions are checked with 2/3/8 people and four clocks. Separate storage and a maliciously mixed shared store are covered; founding in occupied storage is rejected. At each publication boundary, cancellation before/after durable State publication in either workspace overlaps an acknowledged write in its neighbor. Both models must survive warm-cache checks, cold-cache fresh-instance restart and safe retry, without crossing trust/checkpoint/key namespaces. Arbitrary partially restored metadata remains open. |
| Git branches, worktrees, and configuration merges | A real Git/worktree journey checks same-user concurrent publication across a rename/recreated name, conflicting team defaults, refusal before Storage access while conflict markers remain, explicit config merge, detached old-branch writes, preserved personal selection, linked-worktree relocation, and foreign-root rejection. It runs across 2/3/8 people and four clocks. The same journey now rebases an independently changed team default/new environment onto main, requires refusal before Storage access while conflicts remain, explicitly preserves all incarnations, and cherry-picks a legitimate new environment over divergent history. A cleanly applied malicious root commit must still fail the existing trust pin, and reverting it restores every environment. Arbitrary merge/rebase/cherry-pick histories remain unbounded and require further generated cases. |
| Checkout move, clone, and backup recovery | New lost-key checkout restoration and repository-pin founding tests cover parts; arbitrary repository relocation and partial metadata restoration are not fully modeled. |
| OAuth/session lifecycle during collaboration | Native `TestNativeSessionTeamClocks` adds 144 controlled HTTP journeys: 2/3/8 devices × four application clocks × logout/revoked token/account switch/pull-only storage permissions/HTTP 429 throttling/HTTP 503 unavailability × failure before/after durable State publication. The real App credential callback and OCI adapter run against a local registry; a channel pauses one writer at its final manifest request while a peer commits an independent edit. Denied writes must not be acknowledged, durable writes must be recovered exactly, and refreshed credentials must retry the same immutable publication without duplicating it. Reauthentication must retain every acknowledged team value. Transient provider failures must retain the exact peer snapshot without invalidating valid credentials; an error may leave only the selected durable write, while any successful transport retry must produce exactly one complete State. Recovery uses the same credentials and preserves the HTTP status/cause and public-error redaction when an error is returned. A different storage account must not grant workspace admin rights or bypass member removal; explicit readmission, fresh App instances and subsequent writes from every device must converge. Public errors must not disclose synthetic tokens or secret canaries. A bounded smoke runs in ordinary tests and related credential/team changes select the matrix. These are native HTTP tests with fixed application clocks and explicit request gates, not strict trace replay or a real OAuth broker/PKCE/token-vault journey. Actual token expiry, browser authorization, vault persistence and arbitrary overlapping session histories remain open. |
| Registry/bucket permission changes | Generic storage faults and App role checks exist. `TestRemotePermissionLossDuringPagination` adds eight native HTTP cases: OCI/S3 × 401/403 × State discovery/scope enumeration. A valid first page is followed by a denied continuation; the operation must return an error rather than successful or missing storage. Restoring access must let the same client retrieve the exact expected listing. `TestGHCRDeletionAuthenticationChangesAfterListing` adds eight cases across user/organization packages: logout/token-load failure, 401, 403, or token rotation after locating the target version. Logout must preserve its cause and stop before DELETE; denied deletion must not be acknowledged. The same deleter must recover after reauthentication, rotated tokens must be loaded for the DELETE request, repeated removal must report absence and neighboring versions must remain untouched. These tests exercise real adapters against controlled provider responses and a synthetic token callback, not actual cloud ACL/token changes. `TestNativeSessionTeamClocks` adds 24 native team permission-loss worlds across 2/3/8 devices, four application clocks and denial before/after durable publication. Authentication remains valid while the paused writer loses only write permission: HTTP 403 must remain a typed internal cause, peer edits must still be readable as the exact complete model, and further add/sync calls must fail without publishing another State. Restoring write access for the same account must recover uncertain commits and safe retries; the same journey then removes/readmits the device and requires all members to restart and write successfully. This complements the 401/revocation/account-switch cases; it does not establish actual cloud ACL changes, S3 team permission lifecycles, all capability-specific public errors or arbitrary combinations of read/list/write/delete permissions. |
| Real provider semantics | OCI/S3 fixtures are complementary tests. Native pagination permission-loss/recovery cases now verify errors on a denied later page and exact retry results; The native team HTTP matrix now crosses 429 throttling and 503 unavailability with peer publication before/after durability and verifies exact recovery. Pagination together with team publication, prolonged or overlapping throttling, eventual listings, interrupted multipart transfer and remote deletion behavior remain partial. |
| Local filesystem failures | `TestOutputBoundaryClocks` adds 72 record/replay cases with 2/3/8 people and four clocks. Public-mode outputs and hardlinks overlap atomic two-key peer updates, both local-variable preservation/replacement policies, real cancellation, member removal, and fresh-request recovery. After removal, fresh reads, file exports and sync must return not_member without changing local output; explicit readmission and restart restore team convergence. Every output must be one complete accepted snapshot, linked files stay unchanged, Unix output mode becomes 0600, no completed-operation plaintext temporary files remain, and local-only values never enter team storage. Eight native regressions add symlink/hardlink/public-mode replacement plus cancellation/rename-failure preservation and cleanup; six link/mode cases fail against the former direct overwrite. The replacement is created, synced and closed in the destination directory before rename. `TestSaveProjectSurvivesPartialWrite` adds a native Linux/macOS subprocess boundary for shared configuration: a real 32-byte RLIMIT_FSIZE causes EFBIG after a partial write. Failed first saves must leave no configuration; failed updates must preserve the exact previous bytes. After the limit is restored, the same save API must recover the exact new readable configuration without temporary files. The original direct write fails both cases and also overwrites linked targets; production fix #605 writes, syncs and closes a same-directory temporary file before replacement. Additional native tests cover hard/symbolic links, preservation of existing permissions and Unix owner/group, private new configurations and cleanup after rename failure. Explicit save destinations must not overwrite an ancestor workspace; implicit CLI saves still discover the ancestor configuration. A supplementary-group regression verifies that replacement preserves shared group access, and ownership-copy errors occur before replacing the old file. Configuration packages run in the six-platform native core matrix; the kernel file-size-limit cases are Linux/macOS only. This is not a disk-full, power-loss or arbitrary syscall-failure proof. ENOSPC/fsync/close fault injection, hostile parent-directory replacement and Windows ACL enforcement remain open. |
| Actual cancellation and process termination | The operation fault matrix now calls a real operation CancelFunc before each selected storage call and after durable publication/deletion; recovery uses a fresh request context. It asserts both the canceled context and preserved errors.Is cancellation cause, with strict replay, independent before/after-state checks, safe retry, and team convergence. Bounded ordinary regressions cover edit, approval, removal, compaction, purge, and history-dependent file pull. Native OCI/S3 HTTP tests block nine API requests before a response, cancel only after server entry, verify request disconnection and preserved cancellation cause, then require the same client to complete a new listing. Upload bodies are drained before waiting so HTTP/1 disconnect observation is valid. Twenty-four additional HTTP/TLS response-body cases interrupt OCI manifest/header/payload and S3 frame/header/payload reads by cancellation or server disconnect. A successful retry must return the exact original bytes; incomplete data must never be acknowledged as success. Payload cancellation starts only after the caller consumes a prefix. Each case has an unmodified transport control and a fresh-read recovery assertion; TLS trusts only the fixture server. Sixteen native team RPC cases cross edit/removal, disconnect before/after durable publication and four clocks. A peer commits while the RPC writer is paused; a queued workspace switch must not persist after disconnect, secret canaries must not appear in responses/events, and reconnect/readmission must preserve every acknowledged peer write. Native regressions also require external context cancellation to interrupt open pipe input and prevent canceled workspace operations. Process termination inside local writes remains partial. |
| CLI child-process execution and secret masking | Twenty-four native cases launch the real run command and child process while the team atomically edits multiple keys, or removes the reader, with four clocks and masked/unmasked output. A pipe gate fixes ordering after child environment capture. An independent digest requires the complete original snapshot; stdout/stderr must contain exactly the expected masked or explicitly unmasked values. A removed member cannot start another export; explicit readmission and fresh-instance reads must recover the latest team state. Revocation cannot retract plaintext already obtained. Child termination and signal delivery overlapping team changes remain partial. |
| Frontend stale views and repeated submissions | App conflict/seen-head checks and adapter tests exist; actual UI edit/save, workspace switching, double submission, and reconnect sequences are not a complete DST journey. |
| Scale and protocol limits | `TestLargerTeamClocks` adds 252 finite worlds across 9/16/32 devices and four clocks: all eight swarm scenes, the team incident with genuine revoked-author/relocation attacks, and five backup recovery modes with warm/cold caches. The swarm requires every writer to pass its initial read before publication, independently checks all conflict candidates or acknowledged keys, then restarts every client and requires new writes and convergence. Recovery verifies exact two-environment snapshots, retained rollback witnesses, compaction-record hiding and mixed-age backups. A bounded nine-device smoke runs in ordinary tests; related core changes select this family in incremental DST. Replay plans remain bounded to 2–32 devices; invalid sizes are rejected before bootstrap. Random generated workloads still use 2–8 actors. More than 32 participants, other large-team workflow combinations, high revision counts, payload/key/entry limits, maximum protocol head/parent counts and paginated compaction need additional end-to-end boundaries. |
| Storage equivocation between readers | `TestObserverEquivocationClocks` adds 48 record/replay worlds: disjoint or conflicting updates × warm/cold caches × 3/4/8 devices × four clocks. Actual App writes create two signed branches; the store hides a different branch from each writer while other readers see both. Isolated readers must retain their own acknowledged snapshot; combined readers must retain every key or exactly both independent conflict candidates and publication digests. Hiding one of the two equal-generation branches from a reader is not detected (the accepted ADR-26 limitation): the reader reads the other branch, read-only. An independent metadata-only oracle rejects actual recorded payload reads while permitting real header/listing calls. Removing only the pre-decryption checkpoint check must be detected even though the later acceptance check still returns rollback; an error-only oracle previously let this mutation survive. After explicit resolution/sync, hiding the merged head, a higher generation, must reject reads, add and sync without partial secrets, ciphertext reads or attempted remote writes, even with warm signed-header caches and even if stale plaintext equals the resolved content. Restoring the view, restarting all clients and writing from every device must converge. Cold caches are cleared again before each rollback probe. A mutation ignoring a view below the accepted generation must fail the disjoint-view oracle. `TestObserverControlEquivocationClocks` adds 24 Control-view worlds across 4/5/8 devices, four clocks and warm/cold caches. Two admins independently promote different members while each sees only its own valid branch. Full-view readers that are not an admin of both branches must stop reads and writes on the fork; unilateral admins cannot join it. Hiding an accepted Control must reject member/secret/request/conflict/history reads, history diffs, pull, add/edit/delete/import/sync, secret resolution, history restore/compaction, approval/removal/role changes before any ciphertext access or remote mutation. Rejected result-bearing operations must return no partial data. A common admin's next operation joins the fork conservatively; an explicit fresh promotion is allowed, but replacing that history with an older branch having the same role map must still fail. Restored views, fresh instances and acknowledged writes from every device must converge. A mutation discarding persisted Control checkpoint witnesses must fail this journey. Arbitrary simultaneous per-reader Control/State views and combinations with removal, readmission and key updates remain open. |
| Permanent device loss and partial key recovery | Replacement retains a stolen-key attacker. A lost-key journey covers losing a device's key entry across 2/3/8 people and four clocks. A native Manager/vault case verifies a missing private entry does not regenerate the device or rewrite metadata. Hardware-specific loss and process termination during native writes remain partial. |
| Human approval and fingerprint handling | App requires explicit approval; wrong-device selection, fingerprint confirmation/cancellation, and stale approval screens need adapter/UI evidence. |
| Long-lived service workspace selection | Real RPC team disconnect cases queue a workspace selection behind edit/removal and require the original persistent selection to survive cancellation. Native tests reject canceled selection/removal and callbacks after acquiring the workspace lock. Successful cross-workspace switching with overlapping reads, OAuth callbacks and identity work still needs additional cases. |
| First-contact trust and compromised invitations | `TestFirstContactClocks` adds 24 strict record/replay journeys: 2/3/8 established teammates, two newcomers and one attacker (5/6/11 total devices), four clocks and warm/cold caches. Independently expected bootstrap information must reject missing or substituted genesis bytes without publishing or pinning either root; restoring correct storage reuses the first generated identity. A self-consistent malicious first invitation is explicitly accepted by TOFU: the attacker approves/promotes the newcomer, which exercises real admin authority and publishes under that root. Correcting the config must require explicit root confirmation before any remote request. Confirmation must preserve the signing identity and leave membership pending in the real team. Join-request fingerprints and recipients are compared with independently loaded device keys; approving one newcomer must not approve the other. Peer updates during onboarding and later approval must retain every acknowledged team value without importing bait or foreign admin rights. Replaying complete foreign Control/State branches into the same workspace/resource, including States by a now-legitimate signer, must fail closed as rollback without ciphertext reads, partial results, remote writes or changed accepted State heads. This follows the existing unknown-Control contract; it does not claim availability while hostile objects remain. Removing the injected objects must recover exact team state, roles, restarts and new writes from every honest device. A positive control exercises the foreign-payload access guard through an actual Store call; a mutation skipping the early root check must fail even though a later pin check still rejects. Human/UI confirmation, miscommunicated independent roots and arbitrary invitation histories remain open. TOFU cannot authenticate an unverified first root. |
| Mixed client/protocol versions | Strict replay uses one build. Unknown signed object versions, unsupported recipient algorithms, and rolling client updates require explicit acceptance/rejection contracts and complementary client fixtures. |
| Secret disclosure through outputs and diagnostics | Map and dotenv round-trips are checked; logs, errors, process arguments, RPC replies, editor messages, crash artifacts, and deleted local outputs need canary-secret assertions across success and failure paths. |
| Adversarial resource exhaustion | A request-flood journey checks that 10,001 untrusted request refs are rejected before fetching, membership stays unchanged, secret work continues, and explicit readmission resumes after cleanup (2/3/8 people × four clocks). A second journey puts a genuine conflicting recipient request at position 257 and requires approval to reject it despite the 256-entry display cap; both journeys run across 2/3/8 people and four clocks (24 cases). Protocol regressions bound aggregate invalid request bytes and permit exact count/byte boundaries. Forty-eight metadata-flood clock/device cases add Control/State listing caps, rejected-reference deduplication, refusal before ciphertext/write/delete, local-file preservation, and team recovery after cleanup. Native protocol tests cover aggregate Control/State header bytes, genesis/last-object/exact-byte boundaries, and stable traversal of unlisted Control parents. Discovery response allocation, maximum valid-parent/head graphs, and repeated-invalid-signature scheduling remain partial. |
| Naming, encoding, and platform ambiguity | `TestPortableConfigClocks` checks 15 invalid names across create/rename/switch, case-insensitive create/rename collisions, and a valid case-only rename preserving storage lineage. Ten hand-edited unsafe or colliding output configurations cross read/pull/add/sync/history on every device; rejection must precede Storage access and preserve local/external fixture files. Explicit configuration repair, restart and all-environment convergence run with 2/3/8 people and four clocks (12 record/replay cases). Native config regressions cover the same rejection boundaries plus valid mixed-case config. Five mutations remove load validation, save validation, environment case-fold collision checks, output collision checks or trailing-dot rejection. Output comparisons include omitted defaults and cleaned case-folded paths; rejected operations preserve neighboring environment files. Same-name rename rejection also preserves configuration and personal selection. Creating or renaming an environment whose default output collides with an existing custom output must fail without saving configuration or changing personal selection. Arbitrary Unicode output path normalization, reserved output filenames, parent-directory aliases and OS filesystem rules remain partial. |
| Transport destination and credential boundaries | Native `TestGHCRPackagesRejectsRedirectedAPICalls` adds 120 HTTP/TLS cases across user/organization packages, owner lookup/version listing/deletion, 301/302/303/307/308 and another port/another host/HTTPS-to-HTTP/same-origin redirects. Redirected calls must fail without contacting the destination, disclosing the synthetic token or deleting/acknowledging a version; the same deleter must recover with exactly one target deletion once redirects stop. A separate regression preserves the caller-shared HTTP client redirect policy. The original 90 cross-destination cases reproduced token disclosure or incorrect deletion acknowledgment; the fix is isolated in #602. `TestRemoteTLSCertificateBoundaries` adds 24 native OCI/S3 cases: discovery/header/payload × unknown authority/wrong hostname/expired/not-yet-valid certificate. Each uses real TLS and the same adapter for a valid control, rejected certificate and recovery. Failure must preserve the typed certificate cause and send no HTTP request to the unverified peer; successful reads/listings must return exact fixture bytes/digests. Synthetic keys, certificate dates and verification time are fixed; each S3 request makes one attempt without SDK jitter/backoff. The fixture injects its own CA trust and does not establish system-CA/default-constructor or real-provider coverage. Storage packages now run in the existing native core CI matrix, including Linux ARM, Windows ARM and macOS. These are real HTTP adapter tests against local servers, not deterministic team/provider sessions. OCI/S3 redirects, DNS/destination changes, proxy handling, registry/bucket credential scoping and overlapping team operations remain open. |
| Progress under sustained contention | `TestContentionClocks` adds 120 record/replay cases: add/edit/delete/import/sync × exhaustion/yield-at-last-attempt × 2/3/8 people × four clocks. Genuine peer commits move heads before each final recheck. Exhaustion must return conflict with no own publication or local-file change; every acknowledged peer key survives. If peers yield on the last allowed attempt, the writer must succeed with one publication. Explicit retry after contention stops and fresh-instance restart must restore team progress. Three mutations remove the head recheck, prematurely exhaust retries, or make them unbounded; each must fail behaviorally. Membership/compaction starvation, scheduler fairness, cancellation while waiting, and sustained Control changes remain partial. Safety alone does not establish availability. |
| Coordinated disaster recovery | `TestDisasterRecoveryClocks` adds 120 record/replay cases: retained current checkpoint, all trusted records restored to an old snapshot, or retired encryption keys against current storage; each crosses 2/3/8 people, four clocks and warm/cold caches. Complete fixture backups include configuration, trust pins, checkpoints, personal environment selections, caches and synthetic private-key metadata. Two environments receive atomic multi-key peer updates; Control roles or recipient keys advance before backups of different ages are restored. A retained witness must reject both reads and writes against rolled-back storage. If every trusted checkpoint and storage are restored together, signatures cannot prove freshness: the exact older accepted state is expected, never a mixed snapshot. Retired keys must fail to decrypt current ciphertext. Restoring old device backups against legitimately compacted current storage must recover the exact latest values in both environments, with warm or cold caches. The fixture independently checks that each environment has exactly one remaining State; no record is needed. Restoring old State objects and ciphertext together with the latest Control must reject on devices retaining current checkpoints: the old States are of a lower generation than the deleted history's kept head. Rollback refusals must return no partial secret map; restoring the matching data snapshot must recover every device and allow further team writes. Read/rejection probes must not publish or delete remote objects. The read-only oracle is checked against actual recorded Publish/Delete calls and read-only controls; request data is decoded from the recorder output field, and unknown methods are rejected. Restoring current storage and the correct key backup must preserve every acknowledged latest value and allow new team writes in both environments. An independent mutation removes witness-based rollback rejection. Arbitrary partial file restoration, arbitrary multi-generation mixtures of data snapshots, explicit re-found/readmission recovery, native process termination and hardware vault restoration remain open. |
| Cache lifecycle across authority changes | `TestRetainedObserverClocks` adds 24 record/replay worlds across 3/4/8 devices, four clocks and warm/cold metadata caches. A reader accepts a real teammate State before removal while the founder is shown a view omitting that State, so the removal does not re-encrypt it. After readmission and two disjoint current-author edits, every reader, the one that read the retired-author branch included, must read exactly the two current heads without a rollback or conflict (ADR-26 has no observer exception), and membership, roles, restarts and new writes from every device must be preserved. CI seed 17913170502171862805 exposed an incorrect generated-workload assumption that equal plaintext implies equal accepted ancestry. The minimized four-operation regression fails before the harness fix and passes after every continuing observer synchronizes its accepted branches before the next group. This changes the harness, not the protocol: independent tests retain and resolve the unsealed case. Cache corruption and stale storage also have tests. Warm/cold caches across logout, key retirement, workspace relocation, member removal/rejoin, and compaction need independent comparisons, including cached metadata still present after its remote revision disappears. A warm cache must not grant authority or hide rollback. |
| Local hostile actors and shared machines | Remote storage attackers are modeled. Output leaf hardlinks/symlinks and inherited Unix file modes now have native regression coverage; team output/cancellation journeys cover hardlinks. Other local users replacing parent directories, ownership changes, shared temporary directories, Windows ACLs and process termination with pending temporary plaintext still require OS-level tests. The atomic leaf replacement does not establish a defense against an attacker controlling the destination directory. |
| Signed wire-format ambiguity | `TestSignedWireAttackClocks` checks 40 malformed signed CBOR objects per world across warm/cold caches, 2/3/8 people and four clocks (24 record/replay cases). Control, State and Request cover duplicate/unknown fields, nonminimal/indefinite/tagged/trailing encodings, invalid UTF-8, excessive nesting and wrong protocol domains; Control/Request also reject unsupported encryption/signing algorithms. Malformed bodies retain legitimate author signatures. Direct protocol verification and every team observer must agree on rejection, and no rejected State ciphertext may be opened. Valid controls, subsequent writes, fresh-instance restarts and convergence are required. Native codec tests cover exact/over nesting, array, map and 1 MiB envelope limits. A permissive decoder mutation must fail the behavioral oracle. Future valid schema extensions still require explicit rejection/acceptance fixtures. |
| Read and export consistency during team changes | File-export worlds now overlap atomic multi-key peer edits with cancellation, revocation or key upgrade at an exact ciphertext-read boundary. Every successful output must equal the complete previously accepted snapshot; no old/new mixture or local-only publication is allowed. A removed member cannot begin a new read/export/sync and rejection preserves the existing file; explicit readmission, restart and latest-state convergence are required. Native CLI child-process tests independently cover captured environments during edit/removal/upgrade. Revocation cannot retract plaintext already obtained by a formerly authorized reader. `TestHistorySnapshotClocks` adds 192 strict record/replay cases for history listing and diffs during atomic peer edits, removal/readmission, key upgrade or compaction, across 2/3/8 people, four clocks and warm/cold caches. Fixture publication digests independently define the exact visible history and added/removed/modified keys. An in-flight result must be the captured complete snapshot; compaction may instead expose its complete retained snapshot or safely refuse reclaimed inputs. Fresh calls after removal must reject without partial output. Readmission must preserve ancestry through an unreadable key epoch, including its newly readable re-encryption entry, and a new process must recover the complete peer update. Recorded clock steps exercise ties and backward wall times. A mutation reintroduces ordering after dropping unreadable nodes. Other export adapters and arbitrary multi-stage membership/compaction histories still require further cases. |

These are open gaps, not rows marked covered by being declared outside the
in-memory harness. Transport faults are inapplicable only to operations with no
transport effect; their local state and user-visible failure paths still require
appropriate tests.


### Full-run scheduling

Full exploration uses eight runner groups per native platform, each with four Actions `parallel` lanes. Thirty-two disjoint logical lanes run 32 seeds each: the same 1,024 seeds as the former 16 lanes × 64 and four lanes × 256 seeds. With four runner groups, every Windows lane reached the 330-minute limit after about 56 of 64 seeds (run 42446542441), because `FlushFileBuffers` on checkpoint writes dominates there; eight groups halve each runner's share of seeds and finite cases. Finite cases and mutation experiments use the same global lane count. Regression tests compare the entire seed sets and validate that every runner group owns exactly four distinct lanes. The full matrix permits at most ten concurrent jobs so routine PR checks retain runner capacity; incremental checks retain one runner per platform. Wall-time improvement depends on runner availability and is verified separately from case completeness.
