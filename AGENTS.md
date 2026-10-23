# AGENTS.md

This file provides guidance to Agent tool when working with code in this repository.

## What is enbu

Keyless `.env` management. Encrypts secrets with age for each member's device key and stores only signed ciphertext in a storage the team chooses: any OCI registry (GHCR included) or an S3 bucket prefix. No shared master key: each device has its own age recipient and a separate signing key, and the member list is a signed Control rooted in `enbu.toml`. GitHub sign-in (Authorization Code Flow with PKCE) is used only to reach GHCR and to create repositories from the desktop app.

## Notes

- After writing code, always write tests for the relevant areas.
- Force-pushes are prohibited.
- After changing code, always run `task all/build`, `task all/test`, and `task all/check`.
- When a Linear task is provided, use a branch name like `feat/enbu-01`.
- Manage local issues and architecture decisions with Kotowari in `.kotowari/`.
- Record design decisions as Kotowari ADRs, not Design Docs or Pages. Do not recreate `docs/design/`. ADR numbers cited below (ADR-12 to ADR-14) live in the local Kotowari workspace; the summary here is what a clone of the repository can rely on.
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
cli/                     → cobra commands: auth, init, identity, doctor, member, switch, add, edit, delete, import, run, pull, sync, resolve, history, completion
desktop/                 → Wails desktop app (service layer + bindings)
web/                     → React frontend of the desktop app (and the browser preview)
app/                     → application layer (use-cases)
pkg/config/              → enbu.toml (shared), per-user local state, XDG data dir
pkg/storage/             → untrusted Storage: OCI (oras-go) and S3 backends, Local test fixture
pkg/wsp/                 → workspace security protocol: signed Control DAG, SignedState DAG, join requests, local checkpoints
pkg/merge/               → 3-way merge of concurrent revisions, conflicts
pkg/identity/            → device Identity: hardware P-256 (TPM / Secure Enclave) or X25519 in the OS keyring, plus the signing key
pkg/signing/             → signing keys (P-256 / Ed25519), canonical signatures, DeviceID derivation
pkg/age/                 → encrypt/decrypt with age (hybrid ML-KEM-768 recipients, plus classical X25519 / P-256 tagged recipients)
pkg/keystore/            → OS keyring access; ENBU_BACKEND=text stores the GitHub token in a file (tokens only, never an Identity)
pkg/bundle/              → JSON marshal/unmarshal of secret map, .env serialization
pkg/schema/, pkg/artifact/, pkg/content/, pkg/export/ → Artifact IR (planned formats beyond .env); only pkg/schema/secretmap is used by the app so far
pkg/auth/                → GitHub OAuth broker flow, loopback callback, token persistence
pkg/provider/git/        → git CLI (repository root, remotes)
pkg/provider/github/     → GitHub API client (repository creation from the desktop app)
pkg/process/             → hides the console window of git child processes on Windows
pkg/apperr/              → application error type, codes, and normalization helpers
test/                    → scenario tests (build tag: scenario)
```

## Key design decisions

- Storage never overwrites: every update is an immutable revision (one OCI manifest holding the SignedState and the ciphertext) under a unique content-derived name `s-{scope}-{digest}` in the storage location `enbu.toml` names (Control `c-{digest}`, join request `r-{digest}`; see docs/storage.md). OCI has no atomic conditional update, so concurrent writers publish side by side instead of racing for one tag (ADR-12)
- Storage is untrusted: a ref is a locator, signatures are the authority. Storage write access must never grant membership or the right to publish secret state
- Members are the principals of the signed Control DAG, rooted at the `control_genesis` digest in `enbu.toml`. The age recipient set comes only from the verified Control. Two admins changing members at once fork the DAG; everything stops until an admin runs `enbu member resolve-fork` (ADR-14). Admin/Member only manages membership and is not a data-access permission
- Each revision is a SignedState naming its `Parents` and the ciphertext; readers verify author and signature, set aside heads from non-members, and check the local checkpoint (the heads already accepted) before decrypting. Concurrent heads are merged 3-way (`pkg/merge`); a key changed differently stops reads and writes until `enbu resolve` (ADR-13). The signing key is separate from the encryption key and never stored in Storage
- New devices publish a self-signed join request `r-{digest}` (no authority); an admin approves it from a list after comparing the fingerprint out of band (`enbu member approve`). Approving or removing a member re-encrypts every environment
- `enbu switch` manages environments (create, switch, delete, rename). The environments and the team's `default_env` live in `enbu.toml` (shared); the environment a person switched to, and the previous one, live in the per-user local state in the data directory, keyed by `workspace_id`
- Recipients are shared across environments: there are no per-environment recipient lists, and no policy engine (an OPA/Rego policy is only an idea in ROADMAP.md)
- `sync` command re-encrypts for all recipients and merges any concurrent heads; the app re-checks storage just before publishing and retries a few times if heads keep changing
- Environments are named in storage by the incarnation in `enbu.toml`, so a rename keeps history and re-creating a name starts fresh. Revisions are never trimmed automatically; an admin reclaims storage with `enbu switch --delete NAME --purge` (GHCR deletes through the GitHub Packages API)
- The trust root is the `control_genesis` digest in `enbu.toml`. `WriteConfig` (the desktop settings editor) refuses to change `workspace_id`, `control_genesis`, or where an existing environment is stored (`config_protected`)
- Identities prefer hardware: P-256 in TPM 2.0 / Secure Enclave, encrypted to with age tagged recipients; without hardware, X25519 in the OS keyring. There is no plaintext Identity backend and no SSH key support
- New identities are hybrid ML-KEM-768 + X25519 (keyring) or ML-KEM-768 + P-256 (hardware, ML-KEM seed sealed by the TPM). A recipient set with any classical key is encrypted classically; `enbu identity upgrade` moves a member to a hybrid key through a signed key-update request an admin approves
- Frontends: the CLI has every operation. The desktop app covers everything a member or admin needs day to day (secrets, import, history, conflicts, environments, purging, members and admins, the post-quantum key upgrade). Only fork resolution and terminal tools (`run`, `doctor`) are CLI only, and the GUI error names the CLI command (`docs/adr/0015-desktop-scope.md`)
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
