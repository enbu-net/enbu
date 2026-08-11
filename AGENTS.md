# AGENTS.md

This file provides guidance to Agent tool when working with code in this repository.

## What is enbu

Cross-platform encrypted artifact workspaces backed by OCI. Resources form a signed, immutable graph with typed schemas, named encrypted streams, exact Rego policy revisions, device-specific Grants, and verified WASM transforms. `.env` is one built-in format rather than the core data model.

## Notes

- After writing code, always write tests for the relevant areas.
- Force-pushes are prohibited.
- After changing code, always run `task all/build`, `task all/test`, and `task all/check`.
- When a Linear task is provided, use a branch name like `feat/enbu-01`.

## Commands

```bash
task all/build          # Build CLI and GUI
task all/test           # All tests
task all/check          # Format and lint all code
task cli/build          # Build CLI
task cli/test           # All CLI tests
task cli/test/unit      # Unit tests
task cli/check          # Format and lint CLI code
task gui/build          # Build GUI desktop app
task gui/test           # GUI tests
task gui/check          # Format and lint GUI code
```

## Architecture

```
main.go                  → version injection, signal handling, delegates to cli/
cli/                     → finite typed commands and native file capabilities
tui/                     → metadata-only Bubble Tea client
desktop/                 → payload-free Wails service and bindings
internal/apphost/        → sole production composition root and use-cases
internal/engine/         → graph sealing/opening, publication, transforms
pkg/artifact/            → canonical Resource, Collection, Grant, Commit contracts
pkg/host/                → typed actions, sessions, operations, native capabilities
pkg/workspace/           → canonical v1 workspace configuration
pkg/cas/, pkg/registry/  → local CAS and authenticated OCI discovery/publication
pkg/policy/, pkg/audit/  → bounded Rego evaluation and encrypted audit journal
pkg/plugin/              → verified, capability-restricted WASM transform host
pkg/schema/              → Opaque, SecretMap, Table, ValueTree, FileTree
pkg/auth/                → GitHub OAuth broker flow, loopback callback, token persistence
pkg/keystore/            → protected OS keyring credentials
pkg/platform/            → native path, lock, ACL and transactional writer boundary
pkg/apperr/              → application error type, codes, and normalization helpers
```

## Key design decisions

- `docs/design/artifact-platform-v1.md` is the canonical architecture and security contract.
- Clients receive only opaque session/operation/stream handles and metadata summaries. Secret bytes and native paths never cross Wails JSON.
- All mutations require an explicit base Commit and produce a new signed Commit or a typed conflict. There is no last-write-wins path.
- Ciphertext is chunked and immutable. Access changes publish new Grant envelopes without rewriting payloads.
- Unknown schemas are preserved as opaque streams. New formats are added through built-ins or verified WASM transforms, not client-specific methods.
- WASM has no WASI, filesystem, network, environment, keychain, registry, or action capability and is bounded by input/output, memory, calls, and time.
- Legacy `enbu.toml`, `.enbu.local`, bundle JSON, environment tags, commands, and compatibility adapters are rejected rather than migrated.

## Error handling

- Functions continue to return the standard `error` interface. `AppError` is a concrete implementation, not a separate return type.
- Every error leaving an exported application operation must be normalized to `AppError`. Unclassified errors use the `internal` code.
- Internal packages may return ordinary errors and add context with `%w`. Preserve the cause chain for `errors.Is` and `errors.As`.
- Assign a specific error code only when callers need to change behavior, such as retrying, selecting an exit code, translating a GUI message, or changing screens.
- Never inspect `err.Error()` to control behavior.
- Desktop UI error state and error component props must use `DisplayError`; never render `err.message`, `String(err)`, an HTTP response body, or an `AppError` payload message directly.
- Convert unknown frontend and backend failures with `toDisplayError`. Unknown or invalid codes must display the localized `internal` message; detailed causes belong only in logs.
- Access Wails bindings only through the frontend backend adapter. Every exported Wails `DesktopService` method must return `BindingResponse` through `bindingResult` or `bindingError`.
