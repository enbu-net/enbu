# Artifact Platform v1

Status: normative design, staged implementation

This document is the source of truth for the artifact-platform refactor. It
supersedes the data, policy, and audit model in the existing `.env`-specific
design documents. Those documents describe the legacy implementation until
they are removed.

The keywords MUST, MUST NOT, SHOULD, and MAY are normative. A section being
specified here does not mean that it is implemented. The implementation status
is listed in [Delivery stages](#delivery-stages).

## Purpose and boundaries

enbu manages confidential, versioned data without requiring every data format
to share one semantic structure. A `.env` file, SSH private key, spreadsheet,
firmware image, and custom application object remain different payloads. The
common representation covers identity, encrypted storage, relationships,
history, access, policy, audit, and safe transformation.

The graph is deliberately not a general graph database. It expresses immutable
revision dependencies and typed logical relationships. A graph relationship
never grants access and never causes code to run.

The platform has two core node kinds:

- `Resource`: one or more named byte streams with a schema identifier.
- `Collection`: a set of typed edges to Resources or Collections.

All semantic types, including built-ins, are Resource or Collection schemas.
New Go node kinds MUST NOT be added for individual file formats.

## Names and versions

Public identifiers use `enbu.net`, not the Go module or GitHub organization
name.

| Contract | Identifier |
| --- | --- |
| Artifact model | `artifacts.enbu.net/v1alpha1` |
| Workspace configuration | `config.enbu.net/v1alpha1` |
| Plugin manifest and ABI | `plugins.enbu.net/v1alpha1` |
| Built-in schemas | `schemas.enbu.net/v1alpha1/<Kind>` |
| Built-in edge relations | `relations.enbu.net/v1alpha1/<Relation>` |
| Built-in materializers | `materializers.enbu.net/v1alpha1/<Kind>` |
| Built-in sinks | `sinks.enbu.net/v1alpha1/<Kind>` |

A type reference has the exact form `<dns-name>/<version>/<kind>`. `version`
uses `vN`, `vNalphaN`, or `vNbetaN`, where each `N` is a non-zero decimal
integer. `kind` is 1-63 ASCII alphanumeric characters, starts with an uppercase
letter, and contains no punctuation. The DNS name is lowercase. Identifiers
below `enbu.net` and its subdomains are reserved for the host. Extensions MUST
use a DNS name they control.

The v1 OCI media types are:

| Object | Media type |
| --- | --- |
| Encrypted payload chunk | `application/vnd.enbu.artifact.chunk.v1` |
| Encrypted material manifest | `application/vnd.enbu.artifact.material.v1+cbor` |
| Encrypted access grant | `application/vnd.enbu.artifact.grant.v1+cbor` |
| Encrypted commit | `application/vnd.enbu.artifact.commit.v1+cbor` |
| Commit announcement | `application/vnd.enbu.artifact.announcement.v1+cbor` |
| Plugin package | `application/vnd.enbu.plugin.v1` |
| Audit segment | `application/vnd.enbu.audit.segment.v1+cbor` |

Media types and API versions are independent. Changing either requires an
explicit version change; readers MUST reject unknown major versions.

## Canonical encoding and identity

Normative objects use deterministic CBOR as defined by RFC 8949 section 4.2.1.
Implementations MUST apply this profile before computing a digest or signature:

- map keys are text strings and are ordered by their deterministic CBOR bytes;
- duplicate map keys, indefinite-length items, floats, and CBOR tags are
  rejected;
- integers use the shortest form and signed zero is not representable;
- strings are valid UTF-8 normalized to NFC before validation and encoding;
- unknown fields in a `v1alpha1` normative object are rejected;
- absent optional fields are omitted rather than encoded as `null`;
- payloads are sorted by name and edges are sorted by stable Edge ID;
- all current repeated fields are sets whose source order has no wire meaning.

UUIDs use lowercase canonical text (`8-4-4-4-12`). Digests use lowercase
`sha256:<64 hex characters>`. Sizes and offsets are non-negative 64-bit
integers. Timestamps in commit and audit records use UTC RFC 3339 with exactly
nanosecond precision.

The digest of an object is SHA-256 over its complete canonical CBOR bytes. A
decoder MUST decode, validate, re-encode, and compare bytes before trusting a
digest or signature. This prevents alternate encodings of the same value.

## Artifact model

The logical model below defines the fields; concrete Go types may use stronger
types for UUIDs, digests, and references.

```go
type Revision struct {
	APIVersion string       // artifacts.enbu.net/v1alpha1
	Kind       Kind         // Resource or Collection
	UID        UUID         // stable across revisions
	Schema     TypeRef
	Metadata   Metadata
	Payloads   []PayloadRef // Resource only
	Edges      []Edge
}

type Metadata struct {
	Name        string
	Labels      map[string]string
	Annotations map[string]string
}

type PayloadRef struct {
	Name      string
	MediaType string
	Digest    Digest // digest of the plaintext stream
	Size      uint64 // plaintext byte count
}

type Edge struct {
	ID       UUID
	Name     string
	Relation TypeRef
	Strength EdgeStrength // pinned or logical
	Target   UUID
	Pinned   *SealedRef    // required only for pinned edges
}

type SealedRef struct {
	Revision Digest // canonical plaintext revision digest
	Material Digest // encrypted material manifest digest
	Grant    Digest // encrypted AccessGrant digest
}
```

### Common invariants

- `APIVersion`, `Kind`, `UID`, `Schema`, and `Metadata.Name` are required.
- A UID identifies a logical object. Every content change creates a new
  revision digest without changing that UID.
- Metadata names and edge names are display names, not identities. Renaming
  does not change a UID or Edge ID.
- Names are non-empty NFC strings without control characters, `/`, `\\`, or
  NUL and are at most 253 UTF-8 bytes.
- Payload names are unique within a Resource. Edge IDs and edge names are
  unique within a node.
- A payload media type is a syntactically valid RFC 6838 media type. It does
  not select executable code.
- A Revision has at most 10,000 edges and 1,024 payloads. Its canonical
  metadata and edge description, excluding payload bytes, is at most 16 MiB.
- An unknown custom schema remains valid and opaque. Core operations MUST
  preserve all its streams, metadata, and edges byte-for-byte.

### Resource

A Resource MUST contain at least one PayloadRef and MAY contain relationship
edges. Each named stream is independent; a consumer MUST select streams by
name, never by array position. Streams are immutable and readable through a
bounded streaming API.

Built-in Resource schemas for the first complete cutover are `SecretMap`,
`Opaque`, `FileTree`, `ValueTree`, `Table`, `FindingSet`, and `RegoPolicy`.
Their semantic codecs are separate from this core envelope. Raw SSH keys, TLS
keys, spreadsheets, firmware, archives, and unknown formats use `Opaque` until
a trusted built-in or plugin supplies additional semantics.

### Collection

A Collection MUST have no payloads. Membership uses pinned edges with relation
`relations.enbu.net/v1alpha1/Member`. Membership order is not significant;
Edge ID is the stable identity used by merge operations. A Collection MAY also
contain non-membership logical edges.

A Collection MUST NOT duplicate a target merely because two display names are
desired. The same UID may appear in disconnected roots, but two pinned
revisions of that UID in one strong closure always fail as revision ambiguity.

### Labels and annotations

Labels and annotations are encrypted with the Revision and MUST NOT be copied
to OCI tags, manifests, or annotations.

Keys use the Kubernetes qualified-name shape: an optional lowercase DNS prefix
and `/`, followed by a 1-63 character name. The name starts and ends with an
alphanumeric character and may contain `-`, `_`, or `.` internally. Label
values are 0-63 characters with the same name-character rule when non-empty.
Annotation values are arbitrary valid UTF-8 strings without NUL.

The canonical CBOR encoding of labels and annotations together is at most
256 KiB. Keys with DNS prefix `enbu.net` or any subdomain of it are host-owned.
A plugin or importer MUST NOT create or modify them. Labels and annotations
are inert: they do not select a plugin, resolve a URL, read an environment
variable, change access, or trigger materialization.

## Graph semantics

There are two edge strengths:

- `pinned` is a strong immutable dependency. It fixes the target UID,
  revision, material, and AccessGrant. Pinned edges form a Merkle DAG.
- `logical` is a weak relation to a UID. It may be cyclic, dangling, or point
  to an object with no locally visible revision. It is never followed for
  materialization, encryption, commit closure, or access calculation.

Validation of a pinned root closure MUST reject:

- a cycle;
- a target whose decoded UID differs from `Edge.Target`;
- a digest, signature, material, or Grant mismatch;
- two pinned revisions for the same UID in one closure;
- a Collection member that is not a pinned `Member` edge.

Logical relationships such as `derivedFrom`, `documents`, and `supersedes`
remain query hints. Provenance required for security is stored as pinned input
references in a transform record, not inferred from logical edges.

Possession of an ancestor, Collection, edge, label, or commit does not grant
the ability to decrypt a target. Every pinned reference carries an explicit
Grant reference, and authorization is checked for each material object.

## Material and AccessGrant

Revision semantics and access are separate.

For each Revision, the host generates an internal age X25519 identity and
encrypts the canonical Revision plus its named streams to that identity. The
Material manifest, addressed by `SealedRef.Material`, maps the logical
PayloadRefs to encrypted chunks and records their stream boundaries. PayloadRef
does not contain a ciphertext location; this avoids making the Revision digest
depend on its own encryption. The manifest does not contain plaintext metadata.

An AccessGrant binds exactly one material digest to wrapped copies of the
internal identity for authorized device recipients. Recipient records use
immutable device identifiers and verified X25519 public keys. Usernames and
labels MUST NOT appear in public OCI metadata.

- Adding a recipient rewrites the Grant and the encrypted references that pin
  it; payload ciphertext remains unchanged.
- Removing a wrap from a Grant changes only the declared recipient set. A
  recipient that retained the Material identity can still decrypt all objects
  and Grant bodies encrypted to that identity; this operation MUST NOT be
  presented as revocation or confidentiality narrowing.
- Any recipient-set narrowing that requires confidentiality MUST run
  `access rekey`: create a new Material identity, re-encrypt the Revision and every
  payload stream, and publish a Grant for only the new set. The application host
  MUST enforce this rule rather than relying on clients to discard old keys.
- Multi-input transformation output starts with the intersection of all input
  recipient sets. Access may be broadened only by a separate, policy-approved
  access operation.
- Graph containment never widens or narrows a Grant implicitly.

Age X25519 remains the only recipient encryption mechanism. An SSH key stored
as payload is not a recipient key. Device private keys and signing keys belong
in an explicitly selected OS keystore; production code MUST NOT silently fall
back to plaintext storage.

### Material wire envelope

The decrypted Material manifest has this logical shape. The canonical manifest
is itself encrypted with its Material identity before it is stored.

```go
type MaterialManifest struct {
	APIVersion string
	Recipient  string
	Revision   EncryptedStream
	Payloads   []MaterialPayload
}

type EncryptedStream struct {
	Digest Digest // complete plaintext stream
	Size   int64  // complete plaintext stream
	Chunks []ChunkRef
}

type ChunkRef struct {
	Offset        int64
	PlaintextSize int64
	Ciphertext    Descriptor
}
```

The Revision is encrypted as a stream alongside its payload streams. Payloads
are sorted by name and chunks by plaintext offset. Chunks are independently age
authenticated and MUST be contiguous from offset zero; their aggregate size
and digest MUST equal the corresponding complete plaintext stream. An empty
stream is represented by one authenticated empty chunk. A reader MUST consume
each age stream to EOF and verify both its ciphertext descriptor and plaintext
digest before publishing materialized output.

The sealing API MUST reject a manifest whose Revision or payload stream does
not match the supplied canonical Revision. The opening API MUST take the
expected Revision digest from the surrounding `SealedRef` and reject a
substituted manifest before returning it.

The decrypted manifest is limited to 16 MiB, a Revision has at most 1,024
payload streams, and each stream has at most 10,000 chunks. Implementations MAY
change chunk size without changing plaintext, Revision, or merge identity.

### Device and AccessGrant wire envelope

Every client installation has a random Device ID, a device-only age X25519 key,
and an independent Ed25519 signing key. An enrollment assertion binds both
public keys and the Device ID to a provider-qualified immutable subject. The
assertion is bounded to 64 KiB and is embedded in the encrypted Grant claims so
that a verifier can validate the historical binding rather than trusting a
mutable username or current provider membership.

Enrollment verification MUST be local, deterministic, and bounded. It MUST NOT
perform network, filesystem, environment, clock, or interactive operations.
The issuer enrollment and Ed25519 signature are verified before processing the
remaining recipient assertions, limiting unauthenticated verifier work to one
bounded assertion.

The public AccessGrant envelope contains only its API version and kind, the
Material digest, the digest and ciphertext of its signed claims, and an
unordered set of anonymous age ciphertext wraps. Each wrap contains the same
Material identity encrypted to one verified device X25519 recipient. Device
IDs, subjects, public keys, assertions, policy digest, and issuer are present
only inside the Material-encrypted claims. The recipient count and ciphertext
sizes are observable; recipient identity is not.

The signed claims bind the Material and policy digests, issuer Device ID, the
exact recipient set, each recipient's enrollment assertion and digest, and the
digest of that recipient's anonymous wrap. Opening a Grant MUST verify canonical
encoding, every wrap digest, age authentication through EOF, the complete wrap
set, every enrollment binding, the opener's exact device keys, and the issuer's
Ed25519 signature. A wrap or encrypted claims body copied from another Grant is
therefore rejected.

Device credentials are a canonical, versioned private object stored under one
fixed keychain entry. A credential backend MUST explicitly report OS-protected
storage; a missing, plaintext, or unknown protection level fails closed. The
native Windows, macOS, and Linux implementations arrive in the platform-
security stage.

## Streaming content-addressed storage

All payload, encryption, and registry APIs are streaming. Core interfaces MUST
NOT accept or return whole payload `[]byte` values.

```go
type CAS interface {
	Ingest(context.Context, string, io.Reader) (Descriptor, error)
	Open(context.Context, Digest) (io.ReadCloser, Descriptor, error)
	Has(context.Context, Digest) (bool, error)
}
```

`Ingest` writes to private temporary storage, computes digest and size while
streaming, verifies end-of-stream, then publishes atomically to a local CAS.
Encryption streams from source to CAS. OCI upload streams immutable CAS
objects. Download streams through digest verification and age authentication;
plaintext is not released as a completed materialization until both reach EOF
successfully.

Chunking is an implementation detail of the material manifest. Chunk
boundaries MUST NOT change the logical plaintext digest, Revision digest, or
merge identity. No fixed 10 MiB artifact limit is part of this contract.

## Commit DAG and multi-client concurrency

A Commit is an encrypted, immutable, signed object containing workspace ID,
root SealedRef, pinned policy reference, parent commit digests, actor and device
IDs, operation ID, timestamp, and mutation provenance. A commit has one parent
for an ordinary mutation, multiple parents for a merge, and no parent only for
workspace initialization.

Publication order is payload chunks, material manifests, Grants, Commit, then
a signed `commit-<sha256 hex>` announcement tag. The announcement is the
visibility point. Interrupted publication before it is unreachable but safe;
v1 performs no destructive remote garbage collection.

A mutable head tag MAY be maintained as a cache hint but MUST NOT be used for
correctness. Clients discover announcements, verify them, and compute the
frontier as commits not reachable from any other discovered commit. Concurrent
commits therefore form a visible fork instead of overwriting one another.

Three-way merge is deterministic:

- changes to distinct Collection Edge IDs merge;
- changes to distinct SecretMap keys merge;
- the same SecretMap key changed differently is a conflict;
- concurrent edits to the same Opaque or FileTree Resource are a conflict;
- update versus delete is a conflict;
- concurrent AccessGrant or RegoPolicy changes are a conflict and MUST NOT be
  unioned;
- unknown schema content is opaque and conflicts when both sides change it.

A successful merge creates a multi-parent Commit. Conflicts are structured
results and preserve every revision. Last-write-wins is prohibited. Restore
creates a new child Commit containing the selected old content; it never moves
or deletes history.

Process-local locks protect local configuration, CAS mutation, and
materialization only. They MUST NOT be used as a remote concurrency mechanism,
and MUST NOT be held during network I/O.

## Policy and audit boundaries

OPA/Rego controls which verified device recipients may be added to an
AccessGrant. It does not encrypt data and is not an authority over already
distributed plaintext.

- A policy is an encrypted `RegoPolicy` Resource pinned by the Commit.
- Workspace initialization creates an owner-only Rego v1 policy.
- Missing policy, compile failure, timeout, unavailable identity attributes,
  and unknown decisions deny the requested Grant change.
- OPA evaluation has no filesystem, network, clock, random, `http.send`, or
  custom side-effecting built-ins.
- Evaluation input is bounded host data: action, actor, candidate device,
  workspace, target UID/schema/labels, verified GitHub attributes, and plugin
  digest.
- Policy cannot infer access from graph structure. Each candidate Grant entry
  is evaluated explicitly.

Audit is host-owned and unavailable to plugins. Before releasing plaintext,
running a transform on plaintext, materializing, or publishing a remote Commit,
the host appends and fsyncs an encrypted, device-signed `started` event to a
local hash-chained journal. Failure to persist that event fails closed. A
terminal `succeeded` or `failed` event follows. OCI delivery is asynchronous;
delivery failure does not roll back a completed operation but remains visible
and retryable.

Audit records contain actor/device ID, action, operation ID, ciphertext digest,
result code, and timestamp. They MUST NOT contain payload values, secret names,
labels, annotations, local paths, arbitrary plugin errors, or frontend error
text. Mutation provenance is also signed inside the corresponding Commit.

External Rekor and SIEM delivery are future trusted sinks, not part of the v1
cutover. This model replaces the legacy design that sent plaintext secret names
to Rekor after an operation.

## Restricted WASM Transform

User extensions implement one primitive: a deterministic Transform from
selected immutable input handles to staged output drafts. The host validates,
assigns UIDs and provenance, applies Grants, encrypts, audits, and commits the
outputs. A plugin never mutates the graph or storage directly.

The v1 runtime uses wazero without WASI and exposes only bounded equivalents of
`input_len`, `read_at`, `output_create`, `output_write`, `output_close`, and a
numeric result. Filesystem, network, environment, process, devices, clock,
randomness, keyring, policy, audit, access management, and UI imports are
absent. Each execution uses a fresh instance with context cancellation and
hard limits for memory, time, calls, and output bytes.

Plugins are installed as OCI packages pinned by digest. Signature, issuer,
subject, declared output namespaces, and a local or organization trust grant
are verified before execution. A repository may request a digest but cannot
grant trust. Opening a repository MUST NOT download or execute a plugin.

Custom schemas remain usable as opaque Resources when their plugin is absent.
A firmware Wi-Fi scanner, for example, reads an Opaque firmware Resource and
may stage a FindingSet or SecretMap. It cannot discover devices, change host
Wi-Fi, flash firmware, or write a file; those remain explicit trusted host
operations.

## Portable paths and materialization

Canonical graph objects contain logical paths only. They MUST NOT contain OS
absolute paths, native mode bits, ACLs, ownership, mtime, xattrs, drive letters,
or device names. Shared workspace configuration contains only repository-
relative bindings. Absolute destinations and device-specific selections live
in local state.

FileTree paths are UTF-8 NFC relative paths separated by `/`. Validators on
every OS reject empty segments, `.`, `..`, `\\`, NUL, absolute paths, drive-
relative paths, UNC and device paths, alternate data streams, Windows reserved
names, trailing dots or spaces, case-fold collisions, symlinks, junctions,
reparse points, and hard links.

Materialization uses a host `SecureWriter`: validate the complete target path,
create a private same-directory temporary file, stream and verify digest and
age EOF, sync it, atomically replace the destination, and sync the parent where
supported. Unix private files/directories use `0600`/`0700`. Windows applies an
explicit DACL for the current user and SYSTEM. A busy Windows destination is
left unchanged and returns a structured error.

Platform directory discovery, file locking, secure replacement, browser
launch, protocol registration, and keystore integration use OS-specific
implementations. Portable graph, crypto, policy, plugin, and merge logic MUST
behave identically on Windows, macOS, and Linux.

## Client topology

There is no daemon and no HTTP API. CLI, Bubble Tea TUI, and Wails Desktop link
the same Go application host in-process.

An opened workspace is an immutable session value containing its workspace ID,
fixed root, remote, configuration revision, stores, and platform capabilities.
Operations receive an explicit session and base revision. A mutable global
repository directory is prohibited. Multiple workspaces may be open in one
Desktop process.

Long operations return an Operation ID and publish bounded, sequenced progress
events. CLI signals, TUI cancellation, and Desktop cancellation terminate the
same Go context. Per-workspace mutations are coordinated in process while
immutable reads remain concurrent; the Commit DAG handles other processes and
machines.

Wails is an adapter only. Go owns filesystem access, crypto, policy, audit, and
WASM. File dialogs return paths, after which Go opens the files. Binary and
secret payloads MUST NOT cross Wails JSON bindings. Every exported Wails method
returns the established `BindingResponse` envelope, and frontend errors use
`DisplayError`. Generated bindings are regenerated, not edited. The legacy
HTTP `/api` fallback is removed during client cutover.

## Compatibility rejection

The refactor intentionally has no migration layer.

- Legacy `enbu.toml`, `.enbu.local`, command names, JSON output, Wails methods,
  bundle JSON, media types, `secrets-*` tags, and `recipient-*` tags are not
  read or written by the new application host.
- Detection of a legacy configuration returns a typed unsupported-format or
  uninitialized error before filesystem, keystore, or registry mutation.
- Workspace initialization overwrites legacy configuration only after an
  explicit destructive confirmation.
- Existing OCI objects are not deleted; they are invisible because v1 discovers
  only verified v1 commit announcements.
- Dual-read, dual-write, conversion commands, legacy adapters, and compatibility
  feature flags are prohibited.

Internal package overlap is allowed while the stacked refactor is in progress,
but production clients switch once to the new application host and the legacy
implementation is then deleted.

## Delivery stages

This specification defines the target contract. It does not assert that later
stages are present in the current tree.

| Stage | Required implementation | Status at start of refactor |
| --- | --- | --- |
| 1. Artifact contract | Core types, deterministic CBOR, validation, golden vectors, DAG tests | Implemented in the base stack |
| 2. Crypto and Grants | Streaming age, material manifests, AccessGrant, device enrollment validation | Implemented in this stage |
| 3. Storage and commits | Local CAS, streaming OCI, announcements, frontier and merge | Planned |
| 4. Policy and audit | Rego boundary, owner policy, encrypted local journal and dispatcher | Planned |
| 5. Plugin host | Restricted wazero ABI, trust verification, reference transforms | Planned |
| 6. Platform security | Platform dirs, locks, SecureWriter, native ACL and keystore behavior | Planned |
| 7. Built-in schemas | Opaque, SecretMap, FileTree, views, DotEnv and materializers | Planned |
| 8. Application host | Immutable sessions, operations, configuration and orchestration | Planned |
| 9. Client cutover | CLI, TUI, Wails, removal of the HTTP fallback | Planned |
| 10. Legacy removal | Delete old implementation, update release matrix and documentation | Planned |

Stage 1 MUST test canonical digest equality, malformed and non-canonical CBOR,
all Resource and Collection invariants, pinned-cycle and revision-ambiguity
rejection, logical cycles, reserved metadata namespaces, and unknown custom
schema preservation. Later stages add their own security and native-platform
acceptance tests before production wiring changes.
