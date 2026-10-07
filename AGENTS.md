# AGENTS.md

This file provides guidance to Agent tool when working with code in this repository.

## What is enbu

Keyless `.env` management powered by GitHub. Encrypts secrets with age, stores ciphertext as OCI artifacts on GHCR, and uses Authorization Code Flow with PKCE for authentication. No shared master key — each team member gets their own age recipient key.

## Notes

- After writing code, always write tests for the relevant areas.
- Force-pushes are prohibited.
- After changing code, always run `task all/build`, `task all/test`, and `task all/check`.
- When a Linear task is provided, use a branch name like `feat/enbu-01`.
- Manage local issues and architecture decisions with Kotowari in `.kotowari/`.
- Record design decisions as Kotowari ADRs, not Design Docs or Pages. Do not recreate `docs/design/`.
- Keep `.kotowari/` local and out of Git. Use `kotowari check` after editing workspace files directly.
- The Local storage backend (`local://`) is a test fixture: `local://` is accepted only by builds with `-tags fixture` (`app/storage_local.go`). `task` targets and CI pass the tag; add it to direct `go test` runs of tests that resolve a `local://` URL. Never expose `local://` in user docs or release builds. Do not tag-gate code in dependency packages: tobari drops custom-tagged files of dependencies in the unit coverage run.

## Commands

```bash
task all/build          # Build CLI and GUI
task all/test           # All tests
task all/check          # Format and lint all code
task cli/build          # Build CLI
task cli/test           # All CLI tests
task cli/test/unit      # Unit tests
task cli/test/scenario  # Scenario tests
task cli/check          # Format and lint CLI code
task gui/build          # Build GUI desktop app
task gui/test           # GUI tests
task gui/check          # Format and lint GUI code
```

## Architecture

```
main.go                  → version injection, signal handling, delegates to cli/
cli/                     → cobra commands: auth, init, add, pull, sync, switch
tui/                     → Bubble Tea TUI
desktop/                 → Wails desktop app (service layer + bindings)
app/                     → application layer (use-cases)
pkg/config/              → repo detection (git remote), enbu.toml, XDG data dir
pkg/auth/                → GitHub OAuth broker flow, loopback callback, token persistence
pkg/age/                 → key generation, encrypt/decrypt with age (X25519 only)
pkg/keystore/            → pluggable private key storage (OS keyring or plaintext file)
pkg/signing/             → signing keys (P-256 / Ed25519), canonical signatures, DeviceID derivation
pkg/wsp/                 → workspace security protocol: signed Control chain, SignedState, local checkpoints
pkg/bundle/              → JSON marshal/unmarshal of secret map, .env serialization
pkg/oci/                 → push/pull OCI artifacts to GHCR (oras-go), tag listing, digest checks
pkg/provider/github/     → GitHub API client (org detection)
pkg/apperr/              → application error type, codes, and normalization helpers
test/                    → scenario tests (build tag: scenario)
```

## Key design decisions

- Secrets are stored per environment as OCI manifests tagged `secrets-{env}` on `ghcr.io/{owner}/{repo}-enbu`
- Storage is untrusted: a ref is a locator, signatures are the authority. Storage write access must never grant membership or the right to publish secret state
- Members are the principals of the signed Control chain (`control-head`), rooted at the `control_genesis` digest in `enbu.toml`. The age recipient set comes only from the verified Control; `recipient-*` objects no longer exist. Admin/Member only manages membership and is not a data-access permission
- Each secret state (`secrets-{env}`) is a SignedState naming the ciphertext blob; readers verify author, signature and the local checkpoint before decrypting. The signing key is separate from the encryption key and never stored in Storage
- New devices leave a self-signed `request-{device-id}` (no authority); an admin approves it from a list after comparing the fingerprint out of band (`enbu member approve`). Approving or removing a member re-encrypts every environment
- `enbu switch` manages environments (create, switch, delete, rename) with state tracked in `enbu.toml` (shared) and `.enbu.local` (per-user)
- Access control is delegated to OPA/Rego policy evaluated at sync time — not per-environment recipient lists
- `sync` command re-encrypts for all recipients with optimistic concurrency (digest-based conflict detection + exponential backoff retry)
- Private keys are stored via a pluggable keystore backend (OS keyring by default, plaintext file via `ENBU_BACKEND=text`)
- Only age X25519 keys are used — no SSH key support
- No bot/CI decryption — re-encryption requires a human to run `enbu sync`

## Error handling

- Functions continue to return the standard `error` interface. `AppError` is a concrete implementation, not a separate return type.
- Every error leaving an exported `app` operation must be normalized to `AppError`. Unclassified errors use the `internal` code.
- Internal packages may return ordinary errors and add context with `%w`. Preserve the cause chain for `errors.Is` and `errors.As`.
- Assign a specific error code only when callers need to change behavior, such as retrying, selecting an exit code, translating a GUI message, or changing screens.
- Never inspect `err.Error()` to control behavior.
- Desktop UI error state and error component props must use `DisplayError`; never render `err.message`, `String(err)`, an HTTP response body, or an `AppError` payload message directly.
- Convert unknown frontend and backend failures with `toDisplayError`. Unknown or invalid codes must display the localized `internal` message; detailed causes belong only in logs.
- Access Wails bindings only through the frontend backend adapter. Every exported Wails `DesktopService` method must return `BindingResponse` through `bindingResult` or `bindingError`.
