# Invariants

The properties enbu's protocol must keep, each with the code that enforces it and the check that tests it.
TLA+ names refer to the models in [tla/](tla/README.md): `Model.PROPERTY` is checked by the model's small and large configs, and every mutant config must break the property it names.
The Go test column links these protocol properties to executable tests.
The implementation-refinement models and their additional tests are indexed separately in [IMPLEMENTATION_INVARIANTS.md](IMPLEMENTATION_INVARIANTS.md); IDs in that table are local to that refinement layer and must not be conflated with the protocol IDs here.

Threat model shared by every model: storage is untrusted (it hides, deletes, replays and accepts anything anyone writes), anyone may write storage, a member's key may sign anything, and a removed member keeps its key.
Nobody can sign with a key they do not hold.

## Membership and authority

| ID | Property | Enforced by | TLA+ | Go test |
|----|----------|-------------|------|---------|
| AUTH-1 | Authority flows only from the parents: every accepted Control but the genesis is signed by its author, an admin of every parent. | `pkg/wsp/control.go` `VerifyChild`; `pkg/wsp/chain.go` `LoadControl` | `ControlDAG.AUTH_1` | TestControlVerifierMatchesTheModel |
| AUTH-2 | Storage write access grants nothing: an outsider never becomes a principal, a member never makes itself an admin. | `VerifyGenesis`, `VerifyChild`, `LoadControl` | `ControlDAG.AUTH_2` | TestMemberCannotSignControl, TestOutsiderCannotSignControl |
| AUTH-3 | Content from a non-member is never read as current. | `pkg/wsp/state.go` `VerifyRevision`, `AuthorIsCurrent`; `app/resource.go` `trustedHeads` | `StateDAG.AUTH_3` | TestReaderMatchesTheModel |
| REJOIN-1 | Once a member was removed, nothing it signed under a Control from before the removal is read as current, even after it is approved again. | `AuthorIsCurrent`, `ControlView.MembershipUnbroken` | `StateDAG.REJOIN_1` | TestReadmittedMemberCannotReviveOldState |
| CP-1 | Storage hiding an accepted Control is detected: a device proceeds only on a view holding every Control it accepted. | `LoadControl` (checkpoint heads), `Checkpoints.AcceptControl` | `ControlDAG.CP_1` | TestLoadControlDetectsAHiddenAcceptedControl |

## Control forks

| ID | Property | Enforced by | TLA+ | Go test |
|----|----------|-------------|------|---------|
| FORK-1 | A fork resolution keeps only the principals every head lists with the same keys, and admin rights every head grants (F4). | `checkResolution`, `ResolveFork` | `ControlDAG.FORK_1` | TestResolveForkIsTheIntersectionInAnyHeadOrder |
| FORK-2 | No device proceeds on a forked Control. | `ControlView.Head`; `app/session.go` `openControl` | `ControlDAG.FORK_2` | TestControlForkStopsAnAdminDemotedOnOneSide |
| FORK-3 | Liveness: a fork does not last while an honest admin of every head opens the workspace, unless storage withholds a Control. | `openControl`, `resolveFork` | `ControlDAG.FORK_3` | TestControlForkIsJoinedByAnAdminsNextOperation |
| FORK-4 | Joining a fork re-encrypts every head under the joined Control. | `resolveFork` → `reencryptAll` | `MemberChange.RESOLVE_1` | TestResolvingAControlForkReencryptsForTheSurvivors |

A fork whose heads share no admin is never joined; see the examples below.

## Recipients

| ID | Property | Enforced by | TLA+ | Go test |
|----|----------|-------------|------|---------|
| RCPT-1 | The recipients of a revision come only from the verified Control it names. | `session.recipients`, `Control.Recipients` | `MemberChange.RCPT_1` | TestSessionEncryptsForControlMembersOnly |
| RCPT-2 | Nothing published after a removal is encrypted for the removed member: a revision's recipients are members of every Control head current when it is published. | `app/publish.go` `controlUnchanged` before and after `Publish` | `MemberChange.RCPT_2` | TestWriteRestartsWhenTheMembersChangeMidway |
| RCPT-3 | A removal whose re-encryption fails leaves the Control unchanged. | `app/members.go` `RemoveMember` (re-encrypt, then publish the Control) | `MemberChange.RCPT_3` | TestRemovalThatCannotReencryptChangesNothing |
| RCPT-4 | Once member changes settle, no head is encrypted for a non-member, except a revision published while a removal was between its re-encryption and its Control. | `reencryptHeads` with `session.removing`; `resolveFork` | `MemberChange.RCPT_4` | TestRemoveMemberReencryptsWithoutThem |
| RCPT-5 | Once member changes settle without a failure, every member can read every head. | `changeMembers` → `reencryptAll` | `MemberChange.APPROVE_1` | TestJoinApproveAndShareSecrets |

## Generations and rollback

| ID | Property | Enforced by | TLA+ | Go test |
|----|----------|-------------|------|---------|
| GEN-1 | A read never succeeds on a view that lost a revision the device accepted, unless a present revision of at least its Generation stands in for it (one a current member signed, or one whose Generation is honest) (F2). | `Checkpoints.CheckState` / `AcceptState`, `StateView.shownGeneration`, `dropWrongGenerations` | `StateDAG.GEN_1` | TestStateCheckpointRejectsAViewBelowTheAcceptedGeneration |
| GEN-2 | A rollback is reported only when storage withheld a revision (F1). | `VerifyRevision` (an unknown Control is invalid, not a rollback) | `StateDAG.GEN_2` | TestReaderMatchesTheModel |
| GEN-3 | The accepted Generation never goes down. | `Checkpoints.AcceptState` | `StateDAG.GEN_3` | TestStateCheckpointNeverLowersTheAcceptedGeneration |
| GEN-4 | An honest write never publishes a revision readers must reject: above `MaxGeneration` it is a conflict (F3). | `writeState`, `State.validate` | `StateDAG.GEN_4` | TestNextGenerationNeverWraps |

## Trust roots

| ID | Property | Enforced by | TLA+ | Go test |
|----|----------|-------------|------|---------|
| TRUST-1 | A pinned genesis is never replaced without `--accept-new-genesis`. | `pkg/wsp/trust.go` `Pin`, `Check`; `app/init.go` `ensureControl` | `Founding.TRUST_1` | TestChangedGenesisStopsEveryOperation |
| TRUST-2 | Founding never adopts a genesis someone else signed. | `FindGenesis` (author), `ensureControl` (`founded`), `PinFounded` | `Founding.TRUST_2` | TestFindGenesisRecognisesOnlyTheAuthorsGenesis |
| TRUST-3 | `enbu.toml` names a genesis only after its publish returned. | `foundGenesis`, `ensureControl` | `Founding.TRUST_3` | TestFailedPublishFoundsAgainOnRetry |
| TRUST-4 | A founding retry after a crash or a lost reply is never refused for storage holding only its own genesis. | `foundGenesis` → `FindGenesis` | `Founding.TRUST_4` | TestLostPublishReplyAdoptsTheOwnGenesisOnRetry |
| TRUST-5 | A repository pin never moves to a workspace this device did not found. | `trustFile.conflict` (repository pin) | `Founding.TRUST_5` | TestRepositoryPinModes |

## Writes

| ID | Property | Enforced by | TLA+ | Go test |
|----|----------|-------------|------|---------|
| SYNC-1 | No lost update: once every write returned, the merged content holds every change whose write succeeded. | `app/write.go` `changeResource` (parents = heads read, look again before publishing), `pkg/merge` | `WriteRetry.SYNC_1` | TestStaleListingMakesAForkNotALostUpdate, TestMergeProperties |
| SYNC-2 | A change is applied by one revision at most, across retries. | `changeResource` (`published`, `publishedInRead`) | `WriteRetry.SYNC_2` | TestPublishedAddSurvivesMembershipRetry |
| SYNC-3 | Retries are bounded. | `changeResource` (`maxRetries`) | `WriteRetry.SYNC_3` | TestWriteGivesUpWithAConflictWhenTheMembersKeepChanging |
| SYNC-4 | Members that keep changing end a write as a conflict, never an internal error (F5). | `changeResource` (`errControlMoved`) | `WriteRetry.SYNC_4` | TestMembersChangingOnEveryAttemptIsAConflict |
| SYNC-5 | Liveness: every write returns. | `changeResource` | `WriteRetry.SYNC_5` | TestContentionClocks |

## Cryptography and input

These hold below the models' abstraction (a signature is "who signed", a ciphertext is "who can read"); the Go tests check them.

| ID | Property | Enforced by | TLA+ | Go test |
|----|----------|-------------|------|---------|
| CRYPTO-1 | Secrets are encrypted only to post-quantum hybrid recipients; classical recipients are refused. | `pkg/age` `ParseRecipient`, `EncryptForPublicKeys` | assumed | TestOnlyPostQuantumRecipientsAreAccepted, TestEncryptionRoundTripsOnlyForRecipients |
| CRYPTO-2 | A signature verifies only for its key, domain and exact body; any changed bit is refused. | `pkg/signing` `Verify`, `Message` | assumed (`signer` field) | TestSignaturesRejectEveryBitFlip, FuzzVerifyNeverAcceptsAlteredBodies |
| CRYPTO-3 | A device ID names exactly one signing key. | `PublicKey.DeviceID`, `Control.Validate` | assumed | TestDeviceIDIsInjective |
| CRYPTO-4 | A ciphertext is used only if it is the one the signed State names. | `wsp.ReadCiphertext` | assumed | TestReadCiphertextChecksTheBlobAgainstTheSignedState |
| INPUT-1 | Signed envelopes, Controls, States and join requests decode only in canonical form and within the size limits. | `pkg/wsp/codec.go` `decodeCanonical`, `DecodeSigned`; `maxControls`, `maxRevisions` | n/a | FuzzSignedEnvelope, FuzzControlCodec, FuzzStateCodec, FuzzJoinRequestCodec |
| INPUT-2 | A damaged checkpoint or trust file is refused, never read as empty. | `Checkpoints.read`, `Trust.load` | n/a | FuzzTrustFile, FuzzCheckpointFile |
| INPUT-3 | `.env` content round-trips, and content that cannot is refused. | `pkg/dotenv` `Parse`, `Format` | n/a | TestDotenvRoundTripsGeneratedEnvironments, FuzzRoundTrip |
| INPUT-4 | `enbu.toml` parses to what was written, and its protected fields cannot be changed by the settings editor. | `pkg/config` `ParseProject`; `WriteConfig` | n/a | TestReadWriteConfig, TestWriteConfigProtectsTrustAndStorageLineage |

## Examples and findings

These configs check the implementation itself and are expected to produce a counterexample; `task formal/check` asserts that they still do, and the traces are in [tla/traces/](tla/traces/).
An example pins a limit the design accepts; a finding is open and should become an ordinary invariant once fixed.

| Config | Kind | What TLC shows |
|--------|------|----------------|
| `ControlDAG_example_permanent` | example | A fork whose heads share no admin (two admins removing each other) is never joined. |
| `ControlDAG_finding_removed_admin` | finding | An admin that was removed still signs children of the Controls that listed it, and they verify: it can fork the Control after its removal. |
| `ControlDAG_finding_removed_admin_drops` | finding | Through such a fork a removed admin drops another member: the honest resolution keeps the intersection, so the admin who removed it is out. With no admin common to both heads the fork is permanent instead. |
| `StateDAG_finding_removed_sibling` | finding | `GEN_1_strict`: a removed member signs a child of a present revision with the honest Generation; it is set aside as a head, but its proven Generation still counts in `shownGeneration`, so storage can hide a newer accepted revision behind it. |
| `StateDAG_finding_removal_race` | finding | `GEN_2`, all members honest: a member writes between its removal's re-encryption and the Control that drops it; that head is never re-encrypted and is set aside once the Control is published. A compaction meanwhile deletes the history proving its Generation, so a device that read it reports a rollback, and with no trusted head left the environment cannot be read or written. |
| `StateDAG_finding_member_poison` | finding | `GEN_2_strict`: in the same window a member signs a head above a missing parent; devices that read it accept its Generation and report a rollback once it is set aside. |
| `MemberChange_example_removal_window` | example | `RCPT_4_strict`: a revision published in the same window stays encrypted for the removed member until the next write (it was written while it was still a member; RCPT-2 holds). |
