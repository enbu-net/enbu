# enbu

enbu is a cross-platform encrypted artifact workspace for secrets and other sensitive data. It stores immutable, signed, end-to-end encrypted object graphs in an OCI registry. The v1 model is intentionally not limited to `.env` files.

The canonical architecture and security contract are in [docs/design/artifact-platform-v1.md](docs/design/artifact-platform-v1.md).

## Data model

- Resources have stable UUIDs, typed schemas, Kubernetes-style labels and annotations, named payload streams, and typed graph edges.
- Commits pin the root graph revision and the exact Rego policy revision. Concurrent changes produce explicit conflicts; there is no last-write-wins path.
- Grants wrap a Resource material key independently of ciphertext, so access changes do not require rewriting payloads.
- Unknown extension schemas remain opaque and round-trip safely.

Built-in imports cover opaque files, dotenv/SecretMap, CSV/Table, JSON/ValueTree, and FileTree. An SSH private key, spreadsheet, firmware image, certificate, or embedded-device configuration can be retained as an opaque typed stream without teaching the core its internal structure. FileTree handles related files such as firmware sources containing Wi-Fi SSIDs and passwords while preserving portable logical paths.

Verified WASM transforms provide user-defined schema conversion. Plugins receive only explicitly pinned encrypted inputs through a bounded streaming ABI. They have no filesystem, network, environment, clock, registry, keychain, or host-action capability; package signatures, trust grants, namespaces, memory, calls, output size, and wall-clock duration are enforced by the host.

## Install

```bash
go install github.com/enbu-net/enbu@latest
```

Or download a binary from [Releases](https://github.com/enbu-net/enbu/releases).

## CLI quick start

Authenticate and initialize a workspace with an exact OCI repository:

```bash
enbu auth login
enbu init --registry ghcr.io/OWNER/REPOSITORY-enbu
```

Import common formats or an arbitrary file:

```bash
enbu import-file .env --format dotenv --name application
enbu import-file customers.csv --format csv --name customers
enbu import-file config.json --format json --name configuration
enbu import-file id_ed25519 --format opaque --name deployment-key
```

Import a portable group of files. Native paths stay in the CLI process; only logical paths and opaque input capabilities reach the host:

```bash
enbu import-tree \
  device/wifi.conf=./firmware/wifi.conf \
  keys/id_ed25519=./keys/id_ed25519 \
  --name embedded-device
```

List payload-free metadata and materialize one selected Resource:

```bash
enbu list
enbu history
enbu materialize RESOURCE_UUID output.bin --format Raw --payload content
enbu materialize FILE_TREE_UUID files.tar --format FileTreeTar
```

The CLI never returns plaintext through `--json`. Materialization writes through a host-owned transactional file capability.

## Multi-device enrollment

A candidate creates a signed request. An existing owner approves its exact identity, and the candidate imports the signed assertion before access is granted:

```bash
# candidate
enbu enrollment request github:candidate request.cbor

# owner
enbu enrollment approve request.cbor github:candidate assertion.cbor

# candidate
enbu enrollment import assertion.cbor
```

Access changes publish historical Grant envelope variants so a newly authorized device can verify and traverse the complete reachable Commit history.

## Plugin installation

```bash
enbu plugin install transform.enbu-plugin.cbor trust-grant.cbor
```

Installation verifies both objects and stores only the verified package under its digest. A later typed `TransformAction` must explicitly select the plugin digest, exact input revisions, and host-planned output slots.

## Cross-platform security boundary

Linux, macOS, and Windows use the same semantic contracts with native implementations for private directories, no-follow file capabilities, transactional replacement, audit journal locking, and OS key storage. Symlinks, Windows reparse points and alternate data streams, unsafe UNC/device paths, Unicode/case-fold path collisions, ancestor collisions, and path replacement during open are rejected.

The desktop webview receives only session IDs, operation IDs, progress enums, digests, and metadata summaries. Secret values, native paths selected by dialogs, key material, storage handles, and arbitrary errors do not cross the Wails JSON boundary.

## Development

```bash
task all/build
task all/test
task all/check
```

The three gates include the CLI, TUI, Wails desktop, web frontend, race tests, formatting, linting, and platform builds configured by the repository.
