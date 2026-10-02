# Test coverage

The Linux Coverage workflow uses Tobari v0.13.0 for Go and V8 for React.
It runs every Go package with unit tests, including `pkg/`, `desktop/`, `tui/`,
the root command, and repository tools. Separate suites cover the Go scenarios,
Atago CLI E2E, and Identity E2E (vTPM and OS keyring).

The Go report instruments all production packages and tools. Each test binary
writes to its own directory, preventing package reports from overwriting each
other. Each child CLI invocation also writes a unique JSON and TOON report.
Atago scopes include scenario names and registered command paths; Identity
scopes include the parent test name and command path. Secret arguments are not
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
| `cli/test/coverage/e2e` | Atago CLI processes, including errors and TUI |
| `identity/test/coverage` | Identity E2E parent tests and child CLI processes |
| `coverage/report` | Merge the four Go suites and generate HTML and coverprofile |
| `gui/test/coverage` | All React tests, with HTML and LCOV |

The collector disables the test cache and removes previous data for the suite
being rerun. It invalidates the combined report whenever a suite is collected.
Missing package reports or missing E2E child reports fail collection. Go unit
collection continues through other packages after a test failure, preserving
available results.

## Reports

Open `.tmp/coverage/coverage.html` for Go and
`.tmp/coverage/frontend/index.html` for React. Go source data is in
`.tmp/coverage/<suite>/`, with suite-level JSON in
`.tmp/coverage/{unit,scenario,e2e,identity}.json` and the combined result in
`.tmp/coverage/merged.json`. Raw per-test and per-process TOON files can be
supplied to coding agents. `.tmp/coverage/coverage.out` is a standard Go
coverprofile; `.tmp/coverage/frontend/lcov.info` supports frontend coverage
integrations.

CI publishes `tobari-report`, `tobari-data`, and `frontend-coverage` artifacts.
The Go HTML link appears in the job summary. Available raw reports are uploaded
even after failures; a combined Go report requires data from all four suites.
A failed test still fails the job, even when a report can be generated.

## Interpretation

Unit and Atago builds use Tobari's normal static reachable-scope analysis.
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
