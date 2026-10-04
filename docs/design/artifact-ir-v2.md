# Artifact IR v2

Status: design proposal

## Purpose

Artifact IR v2 is the smallest common representation enbu needs to import, store, transform, and export confidential data without making every format share the same semantics.

The IR describes **what the data is**. It does not describe encryption, membership, storage, history, policy, plugins, or export destinations.

The primary design test is that both of these flows remain natural:

```text
.env -> import dotenv -> SecretMap -> export aws
file -> import opaque -> Opaque -> export file
```

## Non-goals

Artifact IR v2 does not define:

- encryption algorithms or recipient formats;
- workspace membership or authorization;
- storage backends;
- commit/history protocols;
- policy engines;
- plugin installation or trust;
- export destinations or cloud credentials;
- filesystem materialization rules.

Those belong to separate layers.

## Core model

```go
type Artifact struct {
    APIVersion string
    UID        UUID
    Schema     TypeRef
    Metadata   Metadata
    Payloads   []PayloadRef
}

type TypeRef struct {
    Group   string
    Version string
    Kind    string
}

type Metadata struct {
    Name        string
    Labels      map[string]string
    Annotations map[string]string
}

type PayloadRef struct {
    Name      string
    MediaType string
    Digest    Digest
    Size      uint64
}
```

There is one core artifact shape. Resource/Collection node kinds, graph edges, access grants, and sealed references are intentionally excluded from v2.

## Field semantics

### UID

UID is the stable identity of one logical artifact across content revisions.

Changing content does not change UID. Creating a distinct logical artifact requires a new UID.

### Schema

Schema describes the semantic meaning of the artifact.

Built-in examples:

```text
schemas.enbu.net/v1/SecretMap
schemas.enbu.net/v1/Opaque
schemas.enbu.net/v1/FileTree
```

Extension schemas use a namespace controlled by the extension author:

```text
schemas.example.com/v1/DatabaseCredential
```

A schema identifier is inert. Merely reading an unknown schema MUST NOT download code, access the network, open files, load a plugin, or perform any side effect.

An implementation that does not understand a schema may preserve, copy, encrypt, decrypt, and transport the artifact, but semantic operations such as validation, transformation, or export may report that the schema is unsupported.

### Metadata

Metadata follows the Kubernetes-style split:

- `Name`: human-facing display name;
- `Labels`: small machine-selectable classification values;
- `Annotations`: non-identifying auxiliary information for humans and tools.

Schema determines artifact semantics. Labels and annotations MUST NOT change schema interpretation, authorization, encryption behavior, plugin loading, network destinations, or filesystem destinations.

Metadata is confidential artifact content and MUST be encrypted with the artifact. Implementations MUST NOT copy names, labels, annotations, or schema identifiers into public storage metadata unless an explicit future protocol defines that disclosure.

### Payloads

Payloads are named plaintext streams.

`MediaType` describes the byte representation. `Schema` describes the meaning. They are independent.

For example:

```text
Schema:    schemas.enbu.net/v1/SecretMap
MediaType: application/vnd.enbu.secret-map+cbor
```

Payload bytes are not embedded in the Artifact object. The IR carries only:

- payload name;
- media type;
- plaintext digest;
- plaintext size.

The plaintext digest is part of confidential artifact metadata. It MUST NOT be exposed directly as a public storage key or public object identifier.

The storage/sealing layer uses separate ciphertext digests and sizes.

## Built-in schemas

The first implementation should remain deliberately small.

### SecretMap

A map of secret names to secret values.

Dotenv is an import/export format for SecretMap, not a schema itself.

```text
.env
  -> dotenv importer
SecretMap
  -> dotenv exporter
.env

SecretMap
  -> AWS exporter
AWS Secrets Manager
```

The same principle applies to future GCP, Kubernetes, and other exporters.

### Opaque

An uninterpreted byte stream.

Opaque preserves data when enbu has no useful semantic model for it. Semantic operations that require another schema fail rather than guessing.

### FileTree

FileTree is reserved for a later stage. It introduces substantial path, symlink, hard-link, platform, collision, extraction, and materialization security concerns and is not required for the first v2 cut.

## Import, transform, export

Data operations use three concepts:

```text
Import:    external representation -> Artifact
Transform: Artifact -> Artifact
Export:    Artifact -> external system or representation
```

Examples:

```text
dotenv -> SecretMap -> AWS Secrets Manager
dotenv -> SecretMap -> dotenv
file   -> Opaque    -> file
```

Importers and exporters declare which schemas they understand.

External-system constraints belong to the importer/exporter, not to Artifact IR. For example, AWS size limits, account selection, region, endpoint, and naming rules MUST NOT become SecretMap semantics.

Export destinations and credentials come from explicit trusted local configuration or command arguments. Artifact metadata MUST NOT silently select a network endpoint, cloud account, role, local path, or other side-effect target.

## Encoding and identity

Normative Artifact objects use deterministic CBOR.

Readers MUST reject non-canonical encodings, duplicate map keys, invalid UTF-8, unsupported fields for the wire version, and values exceeding defined size/count limits.

Artifact revision identity is SHA-256 over the canonical encoded Artifact object.

Canonical encoding provides one byte representation for one accepted object and avoids ambiguity in signatures, digests, caches, and future commit protocols.

## Security invariants

The v2 implementation MUST preserve these boundaries:

1. **Untrusted storage**
   - Public storage sees ciphertext and unavoidable traffic metadata.
   - Artifact names, labels, annotations, schema identifiers, plaintext digests, and payload contents remain encrypted.

2. **No implicit authority from storage**
   - The existence of a recipient or object in storage does not authorize access.
   - Workspace membership/control is a separate authenticated layer.

3. **No active metadata**
   - Schema, labels, annotations, and payload media types are data, not instructions.
   - They never cause code execution or side effects by themselves.

4. **Bounded parsing**
   - Counts, encoded metadata size, payload count, string lengths, and decoder nesting are bounded.
   - Payload contents are streamed instead of loaded wholesale into memory.

5. **Integrity separation**
   - Artifact plaintext digests identify plaintext content inside the encrypted model.
   - Storage identifiers authenticate ciphertext objects separately.

6. **Key separation**
   - Artifact IR does not encode crypto algorithm choices.
   - Encryption identity and future signing identity are separate concerns.

7. **Fail closed on unknown semantics**
   - Unknown schemas can be preserved.
   - Semantic transforms or exports requiring unavailable schema support fail explicitly.

## Layers outside the IR

The intended architecture is:

```text
Import / Transform / Export
            |
        Artifact IR
            |
          Seal
            |
         Material
            |
       Access Grant
            |
          Storage

Workspace Control -> authorized recipients
Commit/History     -> revisions, concurrency, restore
Identity           -> device keys
```

Artifact IR must remain usable without knowing the implementation details of those surrounding layers.

## Scale and future growth

The IR is designed so growth does not require changing its semantics:

- large payloads use streaming blob storage;
- new data types add schemas instead of new core node kinds;
- new exporters consume supported schemas;
- new crypto algorithms remain below the IR;
- new storage backends remain below the sealing/storage boundary;
- future commit DAGs refer to canonical artifact revisions;
- unknown custom schemas remain transportable.

The first implementation MUST NOT add graph relations, collections, plugin APIs, policy, commit DAGs, or FileTree complexity merely for anticipated future needs.

## First implementation slice

The first v2 implementation should prove only these flows:

```text
.env
  -> import dotenv
SecretMap
  -> encode/decode
SecretMap
  -> export dotenv

SecretMap
  -> fake AWS exporter plan

arbitrary file
  -> import opaque
Opaque
  -> export file
```

Required tests include:

- deterministic canonical digest;
- strict malformed/non-canonical decode rejection;
- unknown custom schema round-trip;
- labels and annotations round-trip without affecting semantics;
- bounded metadata and payload-reference parsing;
- plaintext digest mismatch rejection at the sealing/content boundary;
- large payload streaming without whole-payload allocation;
- exporters rejecting unsupported schemas;
- artifact metadata unable to redirect export destinations.

## Deferred work

After the v2 IR and SecretMap/Opaque flows are stable:

1. Workspace Control and authenticated membership;
2. Material sealing and access grants using the existing Identity abstraction;
3. production AWS/GCP exporters;
4. immutable revision/commit history and multi-writer concurrency;
5. FileTree and secure materialization;
6. explicitly trusted extension/plugin runtime.

Compatibility with the old Artifact Platform stack is not a design constraint.
