# ADR-15: What the desktop app covers

- Status: accepted
- Date: 2026-10-23

## Context

enbu has two interfaces: the CLI and the desktop app (the TUI was removed, see
ROADMAP.md). Every operation lives in `app/`, and each interface calls it. The
desktop app had fallen behind the CLI: after the revision DAG (ADR-12/13/14) and
post-quantum identities landed, it could not promote an admin, delete stored
revisions, import a `.env` file, or move a device to a post-quantum key. A
person who only uses the desktop app got stuck on those tasks, and the audit
found a GUI error message that told users to do something the GUI could not do.

## Decision

The CLI is the reference interface and exposes every operation. The desktop app
covers everything a member or an admin needs day to day, so that a person who
only uses the desktop app never has to open a terminal for routine work:

| Area | Desktop |
|---|---|
| Setup: sign-in, choose a folder, `init`, join request | yes |
| Secrets: list, add, edit, delete, pull, sync | yes |
| Import a `.env` file (`enbu import`) | yes |
| Concurrent edits: choose a value (`enbu resolve`) | yes |
| Environments: create, switch, rename, delete | yes |
| Delete stored revisions (`switch --delete --purge`, `--purge-incarnation`) | yes, admins only |
| Members: approve, remove, promote, demote (`member admin`) | yes, admins only |
| Post-quantum key (`identity upgrade`) and approving key updates | yes |
| History: list, diff, restore | yes |
| Control fork (`member resolve-fork`) | no: the error names the CLI command |
| `enbu run`, `doctor`, `completion`, `--json` output | no: terminal tools |

Rules that follow from this:

- A new operation in `app/` that the table puts in scope ships in the desktop
  app in the same release as in the CLI, or the PR says why not and adds it to
  this table.
- When the desktop app cannot do something, the error it shows names the CLI
  command to run instead. It never tells the person to do something the GUI
  does not offer.
- Destructive or trust-changing actions (removing a member, changing admins,
  approving a device or key update, deleting stored revisions) always go
  through a confirmation dialog. Approving compares the fingerprint first.
- Admin-only actions are shown only to admins. The app layer still checks, so
  hiding is a convenience, not the protection.

Fork resolution stays in the CLI because it is rare, needs an admin who
understands which membership change to keep, and is easier to reason about
with the CLI's text output. Revisit this if forks turn out to be common.

## Consequences

- The desktop service, Wails binding, frontend backend adapter, and mock
  backend gain SetAdmin, UpgradeIdentity, DeleteEnvironmentPurging,
  PurgeIncarnation, and ImportSecrets; the history bindings get a screen; join
  requests show whether they are key updates; and environments carry their
  incarnation so a kept lineage can be purged later.
- Each new `app/` operation is checked against this table when it is reviewed.
