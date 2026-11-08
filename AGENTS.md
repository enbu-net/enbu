# AGENTS.md

This file provides guidance to Agent tool when working with code in this repository.

## What is enbu

Keyless `.env` management. Encrypts secrets with age for each member's device key and stores only signed ciphertext in a storage the team chooses: any OCI registry (GHCR included) or an S3 bucket prefix. No shared master key: each device has its own age recipient and a separate signing key, and the member list is a signed Control rooted in `enbu.toml`. GitHub sign-in (Device Flow) is used only to reach GHCR.

## Notes

- After writing code, always write tests for the relevant areas.
- Force-pushes are prohibited.
- After changing code, always run `task all/build`, `task all/test`, and `task all/check`.
- When a Linear task is provided, use a branch name like `feat/enbu-01`.
- Manage local issues and architecture decisions with Kotowari in `.kotowari/`.
- Record design decisions as Kotowari ADRs, not Design Docs or Pages. Do not recreate `docs/design/`. ADR numbers cited below (ADR-12 to ADR-27) live in the local Kotowari workspace; the summary here is what a clone of the repository can rely on.
- Keep `.kotowari/` local and out of Git. Use `kotowari check` after editing workspace files directly.
- The Local storage backend (`local://`) is a test fixture: `local://` is accepted only by builds with `-tags fixture` (`app/storage_local.go`). `task` targets and CI pass the tag; add it to direct `go test` runs of tests that resolve a `local://` URL. Never expose `local://` in user docs or release builds. Do not tag-gate code in dependency packages: tobari drops custom-tagged files of dependencies in the unit coverage run.

## Commands

```bash
task all/build          # Build CLI, GUI and the VS Code extension
task all/test           # All tests
task all/check          # Format and lint all code
task cli/build          # Build CLI
task cli/test           # All CLI tests
task cli/test/unit      # Unit tests
task cli/test/scenario  # Scenario tests
task cli/check          # Format and lint CLI code
task gui/build          # Build GUI desktop app (desktop/wails/build/bin)
task gui/run            # Run the desktop app against the Vite dev server
task gui/bindings       # Regenerate web/src/bindings after changing desktop.Service or its types
task gui/test           # GUI tests
task gui/check          # Format and lint GUI code, and fail on stale bindings
task vscode/build       # Build the VS Code extension (vscode/dist, vscode/media)
task vscode/package     # Package the extension with this machine's enbu (vscode/enbu-vscode.vsix)
task vscode/test        # VS Code extension tests
task vscode/check       # Format and lint VS Code extension code
```

The desktop app uses Wails v3. On Linux it builds against GTK 4 and WebKitGTK 6.0 (`libgtk-4-dev libwebkitgtk-6.0-dev`), which every Go build of `./...` needs. The `wails3` CLI is pinned in `tools/wails3/go.mod`, apart from the main module.

## Releasing

Cut releases from the GitHub web UI: Actions > Release > Run workflow on `main`, then pick `patch`, `minor` or `major`. The workflow tags HEAD of `main` with the next version (svu), builds, signs, attests and publishes the release, and dispatches the homebrew-tap update. If a run fails after tagging, run it again: it reuses the unreleased tag on HEAD instead of bumping. Edit the release notes on the release page afterwards if needed.

## Architecture

```
main.go                  → version injection, signal handling, delegates to cli/
cli/                     → cobra commands: auth, init, identity, doctor, member, switch, add, edit, delete, import, run, pull, sync, resolve, history, completion
desktop/                 → desktop.Service, free of Wails: every exported method is a frontend operation, returning app result types directly; desktop/wails is the Wails v3 app that binds it (macOS/Windows metadata in packaging/); desktop/rpc serves the same methods, found by reflection, as JSON-RPC over stdio (hidden `enbu rpc --stdio`) for editor extensions
vscode/                  → VS Code extension: shows the web/ UI (built with `build:vscode`) in a webview and relays its calls to `enbu rpc --stdio`; local, trusted workspaces only
web/                     → React frontend of the desktop app (and the browser preview and the VS Code extension): routes/ picks the screen, features/ holds each screen, lib/backend.ts is the only door to the backend (the generated bindings, by their Go method names, or the preview mock); UI strings are Paraglide JS messages in web/messages/{en,ja}.json (`m.<key>()` from the generated, Git-ignored src/paraglide), with error messages as `error_<code>`
app/                     → application layer (use-cases)
pkg/config/              → enbu.toml (shared), per-user local state, XDG data dir
pkg/storage/             → untrusted Storage: OCI (oras-go) and S3 backends, Local test fixture
pkg/wsp/                 → workspace security protocol: signed Control DAG, SignedState DAG, join requests, local checkpoints
pkg/merge/               → 3-way merge of concurrent revisions, conflicts
pkg/identity/            → device keys: one encryption identity and one signing key per workspace, in hardware (TPM / Secure Enclave) or in software (OS keyring, or systemd-creds on Linux without one)
pkg/signing/             → signing keys (P-256 / Ed25519), canonical signatures, DeviceID derivation
pkg/age/                 → encrypt/decrypt with age; post-quantum hybrid recipients only (ML-KEM-768 + X25519, tagged ML-KEM-768 + P-256)
pkg/keystore/            → OS keyring access, systemd-creds (`--user`) files for Linux without a keyring; ENBU_BACKEND=text stores the GitHub token in a file (tokens only, never an Identity)
pkg/dotenv/              → .env parsing and rendering
pkg/auth/                → GitHub Device Flow sign-in, token persistence
pkg/provider/git/        → git CLI (repository root, remotes)
pkg/provider/github/     → GitHub API client (the signed-in user)
pkg/process/             → hides the console window of git child processes on Windows
pkg/fsutil/              → atomic file replacement (WriteFileAtomic) and a rename that retries transient Windows failures
pkg/clock/               → injectable clock for timeouts and timestamps
pkg/apperr/              → application error type, codes, and normalization helpers
test/                    → scenario tests (build tag: scenario)
```

## Key design decisions

- Storage never overwrites: every update is an immutable revision (one OCI manifest holding the SignedState and the ciphertext) under a unique content-derived name `s-{scope}-{digest}` in the storage location `enbu.toml` names (Control `c-{digest}`, join request `r-{digest}`; see docs/storage.md). OCI has no atomic conditional update, so concurrent writers publish side by side instead of racing for one tag (ADR-12)
- Storage is untrusted: a ref is a locator, signatures are the authority. Storage write access must never grant membership or the right to publish secret state
- Members are the principals of the signed Control DAG, rooted at the `control_genesis` digest in `enbu.toml`. The age recipient set comes only from the verified Control. Two admins changing members at once fork the DAG; the next enbu operation of a device that is an admin of every head publishes a Control keeping only the principals and admin rights every head agrees on, and every other device stops with `control_forked` until then (ADR-25). Admin/Member only manages membership and is not a data-access permission
- Each device pins, in one `trust.json` beside the checkpoints (replaced atomically), the first `control_genesis` it verified per workspace ID and the first workspace per enbu.toml path (TOFU). A different root in `enbu.toml` stops every operation with `trust_root_changed` until `enbu init --accept-new-genesis`; a pinned device refuses to found a pinned workspace again, while founding a new workspace moves the repository pin. `enbu.toml` names a new genesis only after its publish returned; a founding retry adopts a genesis of this workspace in storage that this device's signing key signed (a lost reply), and refuses storage holding anyone else's (ADR-27)
- Each revision is a SignedState naming its `Parents`, its `Generation` (1 + the highest parent generation), its `Op` (`write`, `sync`, `restore`, `resolve`) and the ciphertext; readers verify author and signature, set aside heads whose author is not a current member or was removed since the Control the head names (ADR-19), and check the local checkpoint before decrypting. The checkpoint keeps the accepted Control heads and, per resource, the highest accepted Generation; storage showing only lower generations of verified revisions (removed authors' included) is a rollback (ADR-26). Hiding an accepted head behind a sibling of equal or higher Generation is not detected. Concurrent heads are merged 3-way (`pkg/merge`); a key changed differently stops reads and writes until `enbu resolve` (ADR-13). The signing key is separate from the encryption key and never stored in Storage
- New devices publish a self-signed join request `r-{digest}` (no authority); an admin approves it from a list after comparing the fingerprint out of band (`enbu member approve`). Approving a member publishes the Control, then re-encrypts every environment. Removing one first re-encrypts every head of every environment without its recipient under the current Control, then publishes the Control, so nothing a remaining member read is set aside (ADR-26)
- `enbu switch` manages environments (create, switch, delete, rename). The environments and the team's `default_env` live in `enbu.toml` (shared); the environment a person switched to, and the previous one, live in the per-user local state in the data directory, keyed by `workspace_id`
- Recipients are shared across environments: there are no per-environment recipient lists, and no policy engine (an OPA/Rego policy is only an idea in ROADMAP.md)
- `sync` command re-encrypts for all recipients and merges any concurrent heads; the app re-checks storage just before publishing and retries a few times if heads keep changing
- Environments are named in storage by the incarnation in `enbu.toml`, so a rename keeps history and re-creating a name starts fresh. Revisions are never trimmed automatically; an admin removes old ones with `enbu history compact --keep N`, which keeps every head and deletes older revisions with no record: Generation, not the deleted digests, detects a rollback, and history ends at a missing parent (ADR-26). An admin reclaims a whole environment with `enbu switch --delete NAME --purge` (GHCR deletes through the GitHub Packages API)
- The trust root is the `control_genesis` digest in `enbu.toml`. `WriteConfig` (the desktop settings editor) refuses to change `workspace_id`, `control_genesis`, or where an existing environment is stored (`config_protected`)
- Identities prefer hardware: P-256 in TPM 2.0 / Secure Enclave, encrypted to with age tagged recipients; without hardware, a software key in the OS keyring, or on Linux without one in files encrypted by `systemd-creds --user`. There is no plaintext Identity backend and no SSH key support
- Identities are hybrid ML-KEM-768 + X25519 (software) or ML-KEM-768 + P-256 (hardware, the ML-KEM seed encrypted to the hardware ECDH key). Classical recipients are refused. A device changes keys by being removed and joining again
- Frontends: the CLI has every operation, and the GUI (desktop app and VS Code extension) offers the same workspace operations, founding a workspace included (it suggests the same GHCR storage `enbu init` defaults to). `run`, `completion`, `rpc` and history compaction stay CLI only. Neither frontend runs `git init` or creates GitHub repositories; the GUI shows the commands instead
- No bot/CI decryption — re-encryption requires a human to run `enbu sync`

## Error handling

- Functions continue to return the standard `error` interface. `AppError` is a concrete implementation, not a separate return type.
- Every error leaving an exported `app` operation must be normalized to `AppError`. Unclassified errors use the `internal` code.
- Internal packages may return ordinary errors and add context with `%w`. Preserve the cause chain for `errors.Is` and `errors.As`.
- Assign a specific error code only when callers need to change behavior, such as retrying, selecting an exit code, translating a GUI message, or changing screens.
- Never inspect `err.Error()` to control behavior.
- Desktop UI error state and error component props must use `DisplayError`; never render `err.message`, `String(err)`, an HTTP response body, or an `AppError` payload message directly.
- Convert unknown frontend and backend failures with `toDisplayError`. Unknown or invalid codes must display the localized `internal` message; detailed causes belong only in logs.
- Access the generated Wails bindings (`web/src/bindings`, committed) only through `web/src/lib/backend.ts`, and the Wails runtime only through `web/src/lib/platform.ts` (in VS Code it routes the bindings' calls to the extension host). Every exported `desktop.Service` method that returns an error must return it through `withRepo`, `withRepoResult`, `publicError` or `publicInto` (apperrlint checks it), so it fails with a `desktop.Error`: the AppError payload, never an internal cause. The Wails app and desktop/rpc send `desktop.ErrorPayload`.
