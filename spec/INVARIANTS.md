# Security invariants

This file lists the properties enbu must keep, each with an ID, and where each is checked.
The TLA+ models in `spec/tla` and the Go tests refer to these IDs.
`go run ./tools/formalcheck -invariants` fails when an ID below has no check, or when a named TLA+ property or Go test does not exist.

How the checks fit together is described in [docs/testing.md](../docs/testing.md#formal-models).

## Threat model

- Storage is untrusted.
  Anyone with write access can publish, hide, delete and replay any object, and show each device a different subset.
  Listings may be stale.
- The attacker may hold the signing key of a removed member, of a member, or of an admin (the last only where stated).
  It may claim any author with a signature that does not verify.
- Anyone who can commit to the repository can change `enbu.toml`.
- Before a device first pins a trust root, `enbu.toml` is trusted on first use.
- Devices crash at any point; local files are replaced atomically.

## Table

The TLA+ column names `Model.Property`.
The Go column names test functions.
A property stated only in Go (for example arithmetic limits) has `—` in the TLA+ column.

| ID | Property | TLA+ | Go |
|----|----------|------|----|
| AUTH-1 | Storage access, member keys and forged signatures make no Control verify; every principal and admin right comes from an honest admin. | ControlDAG.OnlyHonestControlsVerify | TestMemberCannotSignControl, TestOutsiderCannotSignControl, TestForgedControlIgnored, TestControlVerifierMatchesTheModel |
| AUTH-2 | Only an admin of every parent can sign a verified child Control. | ControlDAG.ChildrenSignedByAdminsOfEveryParent | TestMemberCannotChangeControl, TestControlVerifierMatchesTheModel |
| FORK-1 | A verified resolution keeps only principals and admin rights its parents listed. | ControlDAG.ResolutionsStayInsideParents | TestControlVerifierMatchesTheModel |
| FORK-2 | No session runs on a forked Control; a device that is not an admin of every head stops with `control_forked`. | ControlDAG.NoSessionWhileForked | TestControlForkStopsAnAdminDemotedOnOneSide |
| FORK-3 | Whenever an honest device is an admin of every head, its join verifies and leaves one head. | ControlDAG.ForkCanBeJoined | TestControlForkIsJoinedByAnAdminsNextOperation |
| FORK-4 | An honest join keeps exactly what every head agrees on. | ControlDAG.HonestResolutionIsIntersection | TestControlForkIsJoinedByAnAdminsNextOperation |
| FORK-5 | A concurrent approval never revives a removed member. | MemberChange.RemovedStaysRemoved | TestResolvingAControlForkReencryptsForTheSurvivors |
| CP-1 | A session's Control view contains every Control the device accepted. | ControlDAG.AcceptedNeverHidden | TestLoadControlDetectsAHiddenAcceptedControl, TestControlRollbackDetected |
| CP-2 | The checkpoint names only Controls that verified. | ControlDAG.CheckpointOnlyVerified | TestOpenControlIgnoresForgedControl |
| STATE-1 | A read never adopts a revision the attacker wrote: no forgery, no revision of a removed member. | StateDAG.NoAttackerContentAdopted | TestRemovedMemberIsHistoricalButNotCurrent, TestReaderMatchesTheModel |
| STATE-2 | Honest members never build on what the attacker wrote. | StateDAG.HonestNeverBuildsOnAttacker | TestRemovedMemberCannotWrite |
| REJOIN-1 | A readmitted member cannot revive a revision it wrote before it was removed (ADR-19). | StateDAG.NoAttackerContentAdopted | TestReadmittedMemberCannotReviveOldState, TestSessionSetsAsideAHeadOfAMemberRemovedBeforeItWasAccepted |
| GEN-1 | An honest revision carries 1 + the highest Generation of its parents. | StateDAG.HonestGenerations | TestStateGenerationAndOpMustBeWellFormed, TestLoadStatesChecksGenerationsAgainstPresentParents |
| GEN-2 | A successful read never goes back behind a revision the device adopted whose author is still trusted. | StateDAG.NoUndetectedRollback | TestHidingANewerGenerationIsARollback, TestSessionDetectsStateRollback, TestReaderMatchesTheModel |
| GEN-5 | Accepted limitation: hiding an adopted head behind a branch of equal or higher Generation is not detected. | StateDAG.NoUndetectedRollback | TestStateCheckpointDoesNotDetectAHiddenHeadBehindASiblingOfEqualGeneration |
| GEN-6 | A removed member's key cannot vouch for freshness, so it cannot mask a rollback (F2). | StateDAG.NoUndetectedRollback | TestReaderMatchesTheModel |
| GEN-7 | Generation never wraps: no revision makes the next one impossible to write (F3). | — | TestNextGenerationNeverWraps, FuzzStateCodec |
| AVAIL-1 | Objects without a valid signature or naming an unknown Control change nothing a read decides (F1). | StateDAG.JunkDoesNotInterfere | TestReaderMatchesTheModel |
| AVAIL-2 | A read shown a trusted author's revision is not refused for lack of a trusted head. | StateDAG.TrustedContentReadable | TestRemovalKeepsRemainingMembersReading |
| AVAIL-3 | Once concurrent operations settle, every current member can decrypt every head, unless a write gave up after publishing (F7). | MemberChange.SettledHeadsReadable | TestNewMemberMergesWithoutHistoricalDecryptionKey |
| AVAIL-4 | Without an attacker, founding ends with a working session whatever crashes happen. | Founding.HonestFoundingSucceeds | TestLostPublishReplyAdoptsTheOwnGenesisOnRetry, TestFoundingRecoversWhenThePinWriteFails |
| RCPT-1 | Every revision is encrypted only for members of the Control it names. | MemberChange.RecipientsWithinControl | TestSessionEncryptsForControlMembersOnly, TestRecipientInjection |
| RCPT-2 | A write that begins after the Control removing a member was published never encrypts for it. | MemberChange.NoNewCiphertextForRemoved | TestRemoveMemberReencryptsWithoutThem, TestWriteRestartsWhenTheMembersChangeMidway |
| RCPT-3 | After a removal settles, a head is still encrypted for the removed member only if another device's write overlapped the removal. | MemberChange.SettledHeadsExcludeRemovedUnlessRaced | TestRemovalTakesOverWhatTheRemovedMemberWrote |
| SYNC-1 | A write that reported success is never lost, and a removal takes over what the removed member wrote before it began. | MemberChange.NoLostUpdate | TestStaleListingMakesAForkNotALostUpdate, TestRemovalTakesOverWhatTheRemovedMemberWrote |
| SYNC-2 | Success is reported only for a write storage holds. | MemberChange.NoFalseSuccess | TestPublishedAddSurvivesMembershipRetry |
| SYNC-3 | A write never fails because of its own earlier attempt. | MemberChange.NoSelfConflict | TestPublishedAddSurvivesMembershipRetry |
| ERR-1 | Running out of attempts because members kept changing is a `conflict`, never `internal` (F5). | MemberChange.NoInternalErrors | TestMembersChangingOnEveryAttemptIsAConflict |
| TRUST-1 | Once a device pinned an honest root, it never runs on a root the attacker made, and a session always runs on the pinned root. | Founding.NoAttackerRootAfterPin, Founding.SessionOnPinnedRoot | TestChangedGenesisStopsEveryOperation, TestChangedWorkspaceAndGenesisStillStops, TestAcceptNewGenesisReplacesThePin |
| TRUST-2 | Founding adopts only a genesis this device signed, and never proceeds when its check found another workspace in storage. | Founding.FoundedIsOwn, Founding.NeverFoundOverOthers | TestFindGenesisRecognisesOnlyTheAuthorsGenesis, TestFoundingRefusesAnotherDevicesGenesis, TestPinnedDeviceDoesNotFoundTheWorkspaceAgain |
| TRUST-3 | A device pins only a genesis that verified in storage. | Founding.OnlyVerifiedPinned | TestUnverifiedGenesisIsNotPinned |
| TRUST-4 | `enbu.toml` names a new genesis only after its publish returned. | Founding.TomlNamesPublished | TestFailedPublishFoundsAgainOnRetry |
| CRYPTO-1 | A signature verifies only for its domain, key and exact body; changing any bit refuses it. | — | TestSignaturesRejectEveryBitFlip, FuzzVerifyNeverAcceptsAlteredBodies |
| CRYPTO-2 | A ciphertext decrypts only for its recipients and only to the encrypted plaintext; a changed ciphertext fails. | — | TestEncryptionRoundTripsOnlyForRecipients |
| CRYPTO-3 | A device ID names exactly one signing key. | — | TestDeviceIDIsInjective |
| INPUT-1 | Decoding untrusted bytes never panics, respects its size limits, and accepts only canonical encodings, so one object has one digest. | — | FuzzSignedEnvelope, FuzzControlCodec, FuzzStateCodec, FuzzJoinRequestCodec |
| INPUT-2 | Local files (`trust.json`, checkpoints, `enbu.toml`) that fail to parse are refused, never read as empty trust. | — | FuzzTrustFile, FuzzCheckpointFile, TestTrustRejectsACorruptFileUnlessReplaced |
| INPUT-3 | `.env` parsing and rendering round-trip. | — | FuzzRoundTrip, TestDotenvRoundTripsGeneratedEnvironments |
| MERGE-1 | A 3-way merge does not depend on the order of heads, keeps one-sided changes, and reports every key changed differently as a conflict. | — | TestExhaustiveThreeWayValueMatrix, TestMergeProperties |

## Findings

These came out of the models and the review that wrote them.
F1 to F5 are fixed in the PRs that implement ADR-25 to ADR-27; the models' mutants with the same names fail if a fix is undone.

| ID | Finding | Status | Checked by |
|----|---------|--------|------------|
| F1 | `VerifyRevision` returned `ErrRollback` for a State naming an unknown Control before checking its signature, and `LoadStates` aborted on it: one unsigned object blocked a resource. | fixed upstream | StateDAG mutant `abort-on-unknown-control`, AVAIL-1 |
| F2 | Revisions of untrusted authors counted for freshness, so a removed member's key (with storage hiding the newest revisions) masked a rollback. Counting only revisions whose ancestry is present is not enough: the removed key can sign a chain on top of a visible revision. | fixed upstream | StateDAG mutant `count-untrusted`, GEN-6 |
| F3 | A member could publish `Generation = 2^64-1`; the next write's Generation wrapped to 0 and was refused forever. | fixed upstream | GEN-7 |
| F4 | The verifier accepted any subset of the heads' union as a join, while honest clients publish the intersection. | fixed upstream | ControlDAG FORK-1, FORK-4 |
| F5 | A write that ran out of attempts because members kept changing returned `internal`. | fixed upstream | MemberChange mutant `moved-is-internal`, ERR-1 |
| F6 | A write that overlaps a removal (published after the remover took the heads to re-encrypt) stays the current head, still encrypted for the removed member, until the next write or sync. Its content predates the removal. A sync after the removal's Control would close it. | open, documented | MemberChange witness `SettledHeadsExcludeRemoved`, RCPT-3 |
| F7 | A write that gives up after publishing (members kept changing) leaves a revision a member approved meanwhile cannot decrypt until the next write or sync. | open, documented | MemberChange witness `SettledHeadsReadableStrict`, AVAIL-3 |

## Assumptions the models make explicit

- A removal is effective for a device only once it sees the Control without the member.
  Storage that keeps that Control from a writer which never accepted it can make the writer encrypt for the removed member (MemberChange assumes current listings; ControlDAG shows the checkpoint only protects what a device already accepted).
- Two devices can found the same workspace in one storage at once, because storage has no compare-and-swap.
  Each `enbu.toml` then names its own genesis (Founding witness `WitnessNoConcurrentFounding`).
