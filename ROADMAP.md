# Roadmap

Ideas enbu may pursue later. Nothing here is implemented or scheduled, and items
may change or be dropped.

## Interfaces

enbu supports two interfaces: the CLI (`enbu`) and the desktop app.

### Terminal UI

An interactive terminal UI may return later. enbu shipped a Bubble Tea TUI that
ran when `enbu` was started without a subcommand, but it was removed because:

- its features lagged behind the CLI and the desktop app (for example, it could
  not resolve secret conflicts);
- a terminal UI is hard to build and hard to test, so keeping it at parity
  cost more than it gave users.

A new TUI should reach parity with the CLI and the desktop app and come with a
testing approach before it ships.

## Security

- **Secret leak prevention**: stop `.env` files and hardcoded secrets from being
  committed.
- **Tamper detection**: Sigstore-based signing and verification.
- **Policy control**: OPA/Rego-based policy enforcement.
