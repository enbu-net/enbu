# Review Guide

This document defines what reviewers should verify before approving changes to enbu.
It complements `AGENTS.md`: `AGENTS.md` describes implementation conventions,
while this document describes review criteria.

## Review priorities

Review in this order:

1. Security and secret handling
2. Data integrity and destructive behavior
3. Authentication and authorization
4. Correctness and failure handling
5. Compatibility and user-visible behavior
6. Tests
7. Maintainability

Do not block a change solely for stylistic preferences when the existing code is
consistent and the change is correct.

## Finding severity

### Blocker

A finding is a blocker when the change can reasonably cause one of the following:

- disclosure of secrets, credentials, private keys, or decrypted values
- authentication or authorization bypass
- use of secret material without the intended authorization
- corruption or irreversible loss of user data
- writing plaintext secrets to persistent storage unintentionally
- accepting unauthenticated or integrity-unverified remote data as trusted state
- a race or partial failure that can silently overwrite another user's changes

### Major

A finding is major when the implementation is functionally incorrect or violates
a repository contract, including:

- incorrect state transitions
- broken error handling that changes caller behavior
- failure paths that leave inconsistent local or remote state
- incompatible CLI, config, schema, or storage changes without migration
- platform-specific behavior that breaks a supported platform
- missing validation at a trust boundary

### Minor

A finding is minor when it causes a limited correctness, maintainability, or UX
problem but does not invalidate the change.

Style preferences and speculative future requirements should not be reported as
findings unless they create a concrete problem in the current change.

## Security invariants

Changes must preserve the following properties.

### Secret lifetime

- Decrypted secrets must exist only for as long as they are needed.
- Secrets must not be written to logs, diagnostics, error messages, telemetry,
  crash reports, or user-visible debug output.
- Plaintext secret files must not be persisted unless persistence is an explicit
  feature of the operation.
- Temporary secret files must use restrictive permissions and must be cleaned up
  on both success and failure.
- Environment variables containing secrets should be scoped to the child process
  that requires them.
- Passing secrets through command-line arguments requires explicit justification,
  because process arguments may be observable by other processes or diagnostics.

### Key material

- Private key material must not leave its intended key-storage boundary without
  an explicit design reason.
- New cryptographic constructions must use established libraries and protocols.
- Random values used for cryptographic purposes must come from a cryptographically
  secure source.
- Authentication or user-verification checks must not merely precede a sensitive
  key operation when the security claim requires the key operation itself to be
  protected by that check.

### Remote data

Treat data from GitHub, GHCR, configuration files, imported credentials, and
other external providers as untrusted input.

Validate identifiers, formats, ownership assumptions, and integrity information
before using remote data to make security-sensitive decisions.

## Authorization

Review whether the change increases what a user, device, process, or credential
is allowed to do.

In particular, verify:

- which identity is being authenticated
- which resource that identity gains access to
- where the authorization decision is made
- whether the decision can be bypassed through another code path
- whether cached authorization remains valid for the operation using it

Authentication proves an identity. It must not be treated as authorization by
itself.

## State and concurrency

Operations that modify local or remote state must have a defined behavior for
partial failure.

Review:

- what happens if the process exits between individual writes
- whether a retry repeats an already-completed operation safely
- whether concurrent writers can overwrite each other
- whether optimistic concurrency checks are preserved
- whether local configuration and remote state can diverge
- whether destructive operations clearly identify the object being deleted

A successful retry must not depend on an earlier failed attempt having left
undocumented state behind.

## Error handling

Follow the error contracts defined in `AGENTS.md`.

Review exported application operations for:

- correct `AppError` normalization
- preservation of wrapped causes
- stable error codes where callers branch on behavior
- absence of control flow based on `err.Error()`
- absence of sensitive backend details in GUI or CLI messages

Do not request a new error code unless a caller needs to behave differently for
that condition.

## CLI and user-visible compatibility

Changes to the following are user-facing interfaces:

- commands and subcommands
- flags and arguments
- exit behavior
- configuration files
- local state files
- serialized secret/bundle formats
- OCI artifact layout, tags, or metadata
- desktop and TUI behavior

For incompatible changes, verify that the PR either provides migration behavior
or explicitly establishes that compatibility is not required.

Do not infer compatibility solely from Go API compatibility.

## Platform behavior

When platform-specific functionality changes, verify each supported operating
system independently where its implementation differs.

Pay particular attention to:

- filesystem permissions and paths
- process execution and environment handling
- OS credential/key storage
- build tags
- signals and cancellation
- temporary files

A successful implementation on one platform does not establish correctness on
another platform with a different security primitive.

## Tests

Tests should establish the behavior introduced or changed by the PR.

Review for:

- the normal path
- invalid or malicious input
- relevant failure paths
- cancellation and timeout behavior where applicable
- retry or concurrency behavior where applicable
- cleanup after failure
- regression coverage for fixed bugs

Do not require tests for behavior already covered at the appropriate lower layer.

A test that only reproduces the implementation without asserting an external
contract provides little regression protection.

## Dependencies

For a new dependency, verify:

- it solves a concrete problem that is not already handled adequately
- its security boundary is understood
- its maintenance status is acceptable
- the dependency is used through the smallest reasonable surface
- introducing it does not accidentally expand secret or credential access

Avoid requesting a local reimplementation merely to reduce dependency count when
the dependency provides a security-sensitive primitive that should not be
reimplemented.

## Review comments

A blocking review comment should state:

1. the behavior that is wrong
2. the condition under which it occurs
3. the resulting impact
4. why the current implementation permits it

Prefer concrete failure scenarios over general concerns.

For example:

> `run` adds the decrypted token to the parent process environment. A subsequent
> command started from the same process can therefore inherit the token even after
> the target command exits. Scope the environment change to the child process.

Avoid comments such as:

> This feels unsafe.

Questions, optional improvements, and follow-up work should be clearly separated
from findings that block the PR.

## Approval

Approve when no blocker or major finding remains and the changed behavior is
covered sufficiently to make regressions detectable.

The reviewer does not need to prove that the entire repository is correct.
Review the behavior introduced or affected by the change, including relevant
interactions with existing security and state invariants.
