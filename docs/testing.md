# Test coverage

The Linux Coverage workflow uses Tobari v0.13.0 for Go and V8 for React.
It runs every Go package with unit tests, including `pkg/`, `desktop/`, the root
command, and repository tools. Separate suites cover the Go scenarios and
Identity E2E (vTPM and OS keyring).

The Go report instruments all production packages and tools. Each test binary
writes to its own directory, preventing package reports from overwriting each
other. Each child CLI invocation also writes a unique JSON and TOON report.
Identity scopes include the parent test name and command path. Secret arguments are not
included in these names.

## Run locally

Install the pinned tool, then run the tasks with Docker and an unlocked OS
keyring available. The frontend and Python dependencies use the existing Vite+
and uv setup.

```sh
go install github.com/goccy/tobari/cmd/tobari@v0.13.0
task all/coverage
```

On Linux, a dedicated Secret Service session can be used as in CI:

```sh
dbus-run-session -- sh -eu -c '
  printf "\n" | gnome-keyring-daemon --unlock --components=secrets
  task all/coverage
'
```

Individual tasks:

| Task | Coverage |
|------|----------|
| `cli/test/coverage` | All Go unit tests, with shuffle and race detection |
| `cli/test/coverage/scenario` | Go scenarios against the local OCI registry |
| `identity/test/coverage` | Identity E2E parent tests and child CLI processes |
| `coverage/report` | Merge the three Go suites and generate HTML and coverprofile |
| `gui/test/coverage` | All React tests, with HTML and LCOV |

The collector disables the test cache and removes previous data for the suite
being rerun. It invalidates the combined report whenever a suite is collected.
Missing package reports or missing Identity child reports fail collection. Go unit
collection continues through other packages after a test failure, preserving
available results.

## Reports

Open `.tmp/coverage/coverage.html` for Go and
`.tmp/coverage/frontend/index.html` for React. Go source data is in
`.tmp/coverage/<suite>/`, with suite-level JSON in
`.tmp/coverage/{unit,scenario,identity}.json` and the combined result in
`.tmp/coverage/merged.json`. Raw per-test and per-process TOON files can be
supplied to coding agents. `.tmp/coverage/coverage.out` is a standard Go
coverprofile; `.tmp/coverage/frontend/lcov.info` supports frontend coverage
integrations.

`@vitest/coverage-v8` must match the Vitest version bundled by `vite-plus`
exactly. Vite+ rejects mismatched versions before coverage collection starts.
Renovate does not update the provider independently; when upgrading Vite+,
check its bundled `vitest` dependency, update the provider and lockfile to that
version, and run `task gui/test/coverage`.

CI publishes `tobari-report`, `tobari-data`, and `frontend-coverage` artifacts.
The Go HTML link appears in the job summary. Available raw reports are uploaded
even after failures; a combined Go report requires data from all three suites.
A failed test still fails the job, even when a report can be generated.

## Interpretation

Unit builds use Tobari's normal static reachable-scope analysis.
Scenario and Identity builds use `passed-blocks-only` because Tobari v0.13.0's
static dependency analysis does not preserve build tags for test-only packages.
This mode retains per-test execution mapping and the full instrumentation
metadata, while omitting zero-count candidates from individual scopes.
Tobari HTML uses the originating program's instrumented blocks as the denominator
for these scopes. Consumers of raw JSON must honor `passedBlocksOnly` and source
metadata; absent per-test blocks must not be treated as nonexistent code.

Global coverage uses all instrumented blocks and aggregate counts. Identical
execution ranges do not establish that two tests check the same behavior.
Shared worker goroutines can mix named execution counts; see Tobari's
[known limitations](https://github.com/goccy/tobari#known-limitations).
There is no percentage gate and no automatic removal of overlapping tests.

The `enbucoverage` tag enables CLI report collection only in coverage builds;
normal binaries do not import Tobari. Collection happens after command error
rendering and before `os.Exit`, so error paths are included. Abrupt termination
(e.g. SIGKILL) cannot flush a child report. Native hardware tests still require
real devices and are skipped on ordinary hosted runners. The coverage report
is Linux-specific; the existing native OS CI matrix remains separate.

## Formal models

The five authoritative protocol models from `test/formal-tla` live under
`spec/tla/<Model>/`; [spec/INVARIANTS.md](../spec/INVARIANTS.md) links their
properties to Go tests. `task formal/check` runs their small configurations,
mutants and documented findings; `task formal/check/large` runs larger bounds.
`task formal/model MODEL=WriteRetry` selects one model and `task formal/traces`
regenerates the saved counterexamples.

The executable implementation-refinement models live separately under
`spec/conformance/`. Their own property IDs and tests are indexed in
[spec/IMPLEMENTATION_INVARIANTS.md](../spec/IMPLEMENTATION_INVARIANTS.md).
They supply state dumps for the Go conformance tests; they do not replace
the protocol specification. `task formal/invariants` (part of `all/check`)
validates both tables. Their ID namespaces are intentionally distinct.

| Check | What it does | Task | Where it runs |
|-------|--------------|------|---------------|
| TLA+ models (`spec/tla`) | TLC explores every interleaving of small configurations: the Control DAG, the State DAG and its checkpoint, member removal racing writes and approvals, and founding with trust pins. Storage is an attacker, and devices crash. | `formal/check`, `formal/nightly` | every PR (`Formal models`), nightly with larger bounds |
| Refinement checks (`spec/conformance`) | Each refinement model has mutants (a removed check, an old behavior) that TLC must catch through a named property. Witness invariants must be violated, which proves a configuration reaches what its properties are about. Every action must fire. | `formal/refinement` | every PR |
| Model conformance | TLC enumerates every read and every store of Controls a configuration reaches. Go rebuilds each one with real keys and requires the app's reader (`loadResource`, `trustedHeads`, checkpoint) and `wsp.LoadControl` to decide what the model decided. | `formal/conformance` | every PR (`Model conformance`) |
| Property tests | `rapid` generates inputs for the merge, signatures, device IDs, encryption and `.env`, and shrinks a failure to a minimal case. | `property/deep` (100000 cases) | every `go test` (100 cases), nightly |
| Fuzzing | Every decoder of untrusted bytes and the local trust and checkpoint files. Go minimizes a failing input into `testdata/fuzz`, where it becomes a regression test. | `fuzz/run` | seeds in every `go test`, nightly 10 minutes per target |
| Mutation testing | gremlins changes the code of the security packages; the tests must notice. `tools/mutationcheck` reads gremlins' report and requires each target's efficacy; a surviving mutant is either a missing test or listed as equivalent with a reason. | `mutation/check` | PRs (changed packages), nightly (all) |
| Deterministic simulation | The app end to end against its own oracle, with 33 oracle mutation experiments (see `test/simulation`). | `simulation/test` | see `.github/workflows/simulation.yaml` |

TLC comes from aqua (`yashikota/tlc-static`, a native build that needs no
JVM). Model conformance runs only with `ENBU_REQUIRE_TLC=1`, which the task
sets; without TLC it fails rather than skips. `tools/formalcheck` runs TLC
with a 2 GB heap per process (`-heap`); its fingerprints and queue spill to
disk.

### Adding to a model

- A new property needs an ID in `spec/INVARIANTS.md`, a TLA+ property or a Go
  test, and preferably both.
- A new protocol check should come with a mutant configuration in the same
  model directory; see `spec/tla/README.md`. Refinement checks instead list
  their mutants and witnesses in `spec/conformance/checks.toml`.
- A configuration that should reach a new situation needs a witness.
- Keep the PR tier within a few minutes; larger bounds belong to the nightly
  tier, which checks the same properties.

### Reading a failure

- TLC prints the shortest trace to a violation (breadth-first search).
  `formalcheck` shows it from TLC's first error line.
- A conformance failure prints the model's and the code's decision for the
  same read, with every revision of the read.
- `rapid` prints the minimal failing case and a seed; replay it with
  `-rapid.seed`.
- A fuzz failure leaves the minimized input under `testdata/fuzz/<Fuzz>/`.
