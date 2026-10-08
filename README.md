# 💃 enbu

An end-to-end encrypted `.env` manager with independent Identity and Storage backends.

## Why

Development requires sensitive information like API keys and database passwords, but existing approaches have problems:

- Slack/Discord/Email lack E2EE
    - Confusing characters like `1`, `I`, `l` and italic rendering cause copy-paste errors
    - Every change requires notifying everyone manually
    - Even if you encrypt: the delivery channel for the password or decryption key is often insecure
- Dedicated secret managers?
    - External services come with cost and operational overhead
        - AWS/Google Cloud/1Password require contracts and account management
        - Significant organizational burden in both cost and operations
- Just commit it to Git!
    - Ciphertext persists permanently in Git history
    - Future algorithm weaknesses could allow retroactive decryption

## Features

- **Pluggable storage** — OCI registries or S3-compatible object storage
- **E2E encrypted** — Only each member's local private key can decrypt
- **Simple CLI** — After setup, just `enbu add` and `enbu pull`
<!-- Planned -->
<!--- **Secret leak prevention** — Prevent committing .env files or hardcoded secrets -->
<!--- **Tamper detection** — Sigstore-based signing and verification to detect tampering -->
<!--- **Policy control** — OPA/Rego-based policy enforcement -->

## Install

```bash
go install github.com/enbu-net/enbu@latest
```

Or download a binary from [Releases](https://github.com/enbu-net/enbu/releases).

## Quick Start

### 1. Choose storage

For GHCR, authenticate and specify the registry repository explicitly:

```bash
enbu auth login
enbu init --storage oci://ghcr.io/your-org/your-repo-enbu --oci-auth github
```

Any other OCI registry uses Docker credential configuration by default:

```bash
enbu init --storage oci://registry.example.com/team/secrets
```

For S3, create a bucket first and use the AWS SDK's default credential chain:

```bash
enbu init --storage s3://your-bucket/team/workspace --region ap-northeast-1
```

For an S3-compatible service, also pass `--endpoint https://s3.example.com --path-style`.
See [Storage configuration and tests](docs/storage.md).

### 2. Initialize each member's workspace

`init` creates or reuses a local Identity and a separate signing key, saves a generated
workspace UUID and storage configuration in `enbu.toml`, and updates `.gitignore`.
The first device to run `init` becomes the workspace admin and records `control_genesis`
in `enbu.toml`: the trusted digest every other device verifies the member list against.
Commit and share `enbu.toml`. Each member runs `enbu init` in their own folder.
The UUID binds local Identity and environment-switch state to the workspace, so
moving its folder or changing its storage URL does not select a new Identity.

### 3. Add or edit secrets

```bash
enbu add DATABASE_URL "postgres://..."
enbu add API_KEY "sk-..."
enbu edit API_KEY "sk-new..."

# Environment-specific secrets
enbu add --env dev DATABASE_URL "postgres://dev/..."
enbu add --env prod DATABASE_URL "postgres://prod/..."
```

`add` creates a new secret and fails if the key already exists. Use `edit` to update an existing secret.

### 4. Delete secrets

```bash
enbu delete API_KEY
```

### 5. Pull secrets

```bash
enbu pull  # Writes to .env file
enbu pull --env dev  # Writes to the configured output for dev
```

### 6. Add a team member

Being able to write to storage does not make anyone a member. A new member runs `enbu init`
inside the repository (with the shared `enbu.toml`), which leaves a join request and prints the
device fingerprint, for example `a1b2-c3d4-e5f6-0718-293a`. Send that fingerprint to an admin
over another channel (chat, in person). The admin then picks the request from a list:

```bash
enbu member approve     # choose the request, compare the fingerprint, confirm
enbu member requests    # list devices waiting for approval
enbu member list        # list members
enbu member remove      # remove a member and re-encrypt without them
```

Approving re-encrypts every environment, so the new member can `enbu pull` right away.
In scripts, pass `--device <fingerprint-or-device-id>` (and `--yes` to skip the prompt).
The TUI (`enbu`) and the desktop app have the same approval list on their Members screen.

Removing a member cannot revoke secrets that device already read: rotate them.

## Environments

Manage environments with `enbu switch`:

```bash
enbu switch -c dev          # Create and switch to dev
enbu switch -c prod         # Create and switch to prod
enbu switch dev             # Switch to dev
enbu switch -               # Switch back to previous
enbu switch -l              # List environments
enbu switch -d staging      # Delete an environment
enbu switch -m old new      # Rename an environment
```

Define environments in `enbu.toml`:

```toml
version = "v1alpha2"
workspace_id = "11111111-1111-4111-8111-111111111111"
default_env = "dev"

[storage]
url = "oci://ghcr.io/your-org/your-repo-enbu"
oci_auth = "github"

[env.dev]
output = ".env.dev"

[env.prod]
output = ".env.prod"
```

Use `-e`/`--env` with `add`, `edit`, `delete`, `pull`, and `sync` to override the current environment. Recipients are shared across all environments — Without `-e`, enbu uses the environment set by `switch`.

## Identity storage

New workspace identities prefer TPM 2.0 on Linux and Windows, and Secure Enclave on macOS.
Hardware P-256 private keys stay on the device. Encryption uses age Tagged Recipients;
X25519 recipients can be included in the same encrypted file.

| OS | Hardware | Fallback for new identities |
|----|----------|-----------------------------|
| Linux | TPM 2.0 (`/dev/tpmrm0`, then `/dev/tpm0`) | Secret Service (GNOME Keyring / KWallet) |
| Windows | TPM 2.0 through TBS | Credential Manager |
| macOS | Secure Enclave | Keychain |

```bash
enbu doctor                  # No authentication or persistent key creation
enbu identity create         # Create or reuse this workspace's local Identity
enbu identity show           # Backend, algorithm, recipient and device
export ENBU_IDENTITY_BACKEND=auto  # Default: hardware if available, otherwise keyring
# Other choices: hardware (required), keyring (X25519 stored in the OS keyring)
```

Fallback is allowed only when hardware is unavailable before creation begins.
Creation errors and saved-key load errors never silently replace the key.
`init` registers the saved recipient and reuses it after a registration failure.
Hardware identities have no private-key export API. TPM metadata contains encrypted
child blobs bound to the original TPM; Secure Enclave metadata contains a Keychain
reference. Secure Enclave keys require the device to be unlocked and do not prompt
for Touch ID on every use.
On macOS, permanent Secure Enclave storage requires access to the data-protection
Keychain through the executable's signing entitlements and a user login session.
`doctor` checks this access without creating a permanent key. Unsigned standalone
builds may use the OS keyring fallback instead.

Version 1 metadata is stored under `identities/` in enbu's local data directory
(`$XDG_DATA_HOME/enbu` when set; otherwise the platform's application data directory).
Old identities are not migrated or loaded. Plaintext Identity storage is removed.
`ENBU_BACKEND` configures authentication token storage only and does not select an Identity backend.

Identity E2E runs on Linux, Windows and macOS with a pinned test-only vTPM SDK and
local OCI HTTP fixture. Run `task identity/test/e2e` with an unlocked OS keyring.
The normal CLI excludes the software TPM transport. On a real TPM or Secure Enclave
device, run `ENBU_TEST_NATIVE_IDENTITY=1 go test -v ./pkg/identity` for native integration tests.
Hardware device validation is separate from the required GitHub-hosted E2E matrix.
On a real Linux or Windows TPM, run the complete CLI lifecycle against local HTTP
fixtures with `ENBU_TEST_NATIVE_IDENTITY=1 go test -v -count=1 -timeout=5m -tags=identitye2e -run '^TestNativeTPMCLI$' ./test/identitye2e`.
This uses a production CLI build, temporary repository data and the host TPM,
covering init/add/pull/edit/sync/history and Identity reload between CLI processes.

## JSON output

Pass `--json` to any command when invoking enbu from a process such as a VS Code extension.
The command writes exactly one JSON value to stdout.

```json
{"ok":true,"data":{"action":"add","environment":"dev","key":"API_KEY"},"warnings":[]}
{"ok":false,"error":{"message":"secret \"API_KEY\" already exists"}}
```

Successful commands exit with status 0.
Errors are also written to stdout as JSON and exit with status 1.
`enbu pull --json` does not write an `.env` file; it returns the decrypted secrets in `data.secrets`.
Do not log or persist this response.
`enbu auth login --device --json` is unsupported because Device Flow must display a code before authentication finishes.
Use `enbu auth login --json` for browser authentication.

## Test coverage

The Coverage workflow publishes Tobari reports for all Go unit tests, scenarios,
CLI E2E, and Identity E2E, plus React coverage. See [test coverage](docs/testing.md)
for local commands and report usage.

## How It Works

```
Storage (OCI registry / S3 prefix / Local directory)
├── c-{digest}                          ← Signed member list (each one names its parent)
├── r-{digest}                          ← A device asking to join (carries no authority)
└── s-{scope}-{digest}                  ← A revision of one environment: signed state + ciphertext
```

Storage is untrusted. A name is only a locator; signatures are the authority:

- **Nothing is overwritten.** Every update is a new revision named after its own digest, so two
  people saving at the same time publish side by side and neither update is lost. The next
  reader merges them like Git: different secrets combine, and a secret changed in two ways
  stops until someone runs `enbu resolve`.
- **Signed Control** lists the trusted devices, their signing keys and age recipients. Each new
  Control is signed by an admin of its parent, starting from the genesis digest in `enbu.toml`.
  If two admins change the members at once, the Control forks and everything waits for
  `enbu member resolve-fork`.
- **Signed State** binds a ciphertext digest and its parent revisions to the device that wrote
  it. Readers verify the author and signature before decrypting, and set aside anything a
  non-member published.
- **Local checkpoints** remember the Control and State heads this device accepted, so storage
  cannot silently hide them. A delayed listing is retried, not treated as lost data.
- The recipient set is built only from the verified Control. The signing key is a separate keypair
  from the encryption key (hardware P-256 when available, Ed25519 in the OS keyring otherwise) and
  is never written to storage.

Not covered: storage denying service, hiding the newest revision from a fresh device with no
checkpoint, a malicious admin, stolen admin keys, and a removed member who can still write to
storage publishing a revision that claims the control they knew.

1. `enbu add` — Creates a new secret, encrypts for the verified members, signs a new revision, and publishes it
2. `enbu edit` — Updates an existing secret and publishes a new revision
3. `enbu delete` — Removes a secret and publishes a new revision
4. `enbu pull` — Merges the current revisions, decrypts with your private key, writes to `.env`
5. `enbu sync` — Re-encrypts and re-signs for the current member list
6. `enbu resolve` — Chooses between a secret that two people changed at the same time

### GitHub authentication & initialization flow

```mermaid
sequenceDiagram
    participant User
    participant CLI as enbu CLI
    participant Auth as auth.enbu.net
    participant GitHub as GitHub OAuth
    participant GHCR as Storage

    User->>CLI: enbu auth login
    CLI->>CLI: Start 127.0.0.1 callback listener
    CLI->>Auth: Create PKCE session
    Auth-->>CLI: GitHub authorization URL
    CLI-->>User: Open browser
    User->>GitHub: Authorize in browser
    GitHub-->>CLI: Authorization code via loopback callback
    CLI->>Auth: Exchange code with PKCE verifier
    Auth-->>CLI: Access token
    CLI->>CLI: Store token in OS keychain
    CLI-->>User: ✓ Authenticated

    User->>CLI: enbu init
    CLI->>CLI: Create or load repository Identity and signing key
    CLI->>GHCR: Create the genesis Control (first device only)
    Note over GHCR: The genesis digest is saved in enbu.toml
    GHCR-->>CLI: Done
    CLI-->>User: ✓ Initialized
```

### Secret Addition Flow

```mermaid
sequenceDiagram
    participant User
    participant CLI as enbu CLI
    participant GHCR as Storage

    User->>CLI: enbu add KEY VALUE
    CLI->>GHCR: Fetch the Control DAG and verify the signed chain
    GHCR-->>CLI: Verified members
    CLI->>CLI: Encrypt with age for the members' recipients
    CLI->>CLI: Sign the state with the signing key
    CLI->>GHCR: Publish a new revision beside the current ones
    GHCR-->>CLI: Done
    CLI-->>User: ✓ Secret added
```

### Member Addition Flow

```mermaid
sequenceDiagram
    participant New as New Member
    participant Admin as Admin
    participant CLI as enbu CLI
    participant GHCR as Storage

    New->>CLI: enbu init (shared enbu.toml)
    CLI->>GHCR: Verify Control from the genesis digest
    CLI->>GHCR: Write request-{device-id} (no authority)
    CLI-->>New: Waiting for approval, fingerprint a1b2-c3d4-...

    New-->>Admin: Fingerprint, over another channel
    Admin->>CLI: enbu member approve
    CLI->>GHCR: List requests, show the fingerprint
    Admin->>CLI: Confirm the fingerprint matches
    CLI->>GHCR: Append a Control signed by the admin
    CLI->>GHCR: Re-encrypt and re-sign every environment

    New->>CLI: enbu pull
    CLI->>GHCR: Verify Control and State
    CLI->>CLI: Decrypt with private key
    CLI-->>New: Write .env
```
