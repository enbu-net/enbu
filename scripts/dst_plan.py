"""Select affected deterministic simulations; scheduled/manual runs explore all."""

import json
import os
import re
import subprocess
from datetime import UTC, date, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SIM = ROOT / "test" / "simulation"

PLATFORMS = [
    {"target": "linux-amd64", "runner": "ubuntu-26.04"},
    {"target": "linux-arm64", "runner": "ubuntu-26.04-arm"},
    {"target": "darwin-arm64", "runner": "macos-15"},
    {"target": "windows-amd64", "runner": "windows-2025"},
    {"target": "windows-arm64", "runner": "windows-11-arm"},
]

# A full exploration of every platform takes about 90 runner-hours, most of it
# on Windows, so a nightly run of all five ran well into the next working day
# and held DST runners while pull requests queued. Each night explores both
# Linux platforms and one of the slower ones in turn, so every platform still
# gets the complete exploration every third night; a manual run explores all.
ROTATION = ["darwin-arm64", "windows-amd64", "windows-arm64"]


def platforms(mode: str, event: str, day: date) -> list[dict]:
    if mode != "full":
        # A push holds one DST runner instead of five.
        return PLATFORMS[:1]
    if event != "schedule":
        return PLATFORMS
    tonight = ROTATION[day.toordinal() % len(ROTATION)]
    return [
        p
        for p in PLATFORMS
        if p["target"].startswith("linux-") or p["target"] == tonight
    ]


SCENARIO_SOURCES = {
    "file_lifecycle.go",
    "signature_attack.go",
    "locked_device.go",
    "rejected_edits.go",
    "request_attack.go",
    "secret_formats.go",
}

# Shared implementation changes deliberately widen the affected test set.
DOMAINS = {
    "secrets": {
        "simulation",
        "concurrent_matrix",
        "swarm",
        "generated_groups",
        "generated_team",
        "state_matrix",
        "workload",
    },
    "history": {"history_race", "compaction_race", "merge_matrix", "state_matrix"},
    "members": {
        "team_matrix",
        "admin_race",
        "compound",
        "workload",
        "state_matrix",
        "acceptance_matrix",
    },
    "trust": {
        "bootstrap",
        "team_matrix",
        "admin_race",
        "compound",
        "restart",
        "acceptance_matrix",
    },
    "merge": {"merge_matrix", "concurrent_matrix", "swarm", "generated_groups"},
    "clock": {"clock", "compound", "compaction_race", "history_race"},
    "files": {"workload", "state_matrix", "output_boundary"},
    "identity": {"identity", "team_matrix", "compound", "workload"},
}


def names(path: Path) -> set[str]:
    return set(re.findall(r"^func (Test\w+)\(", path.read_text(), re.MULTILINE))


def select(paths: list[str], full: bool = False) -> dict:
    files: set[Path] = set()
    broad = full
    mutation = full
    merge = full
    scenarios = False
    for path in paths:
        if path in {"go.mod", "go.sum"}:
            broad = mutation = merge = True
        elif path.startswith("test/simulation/"):
            source = Path(path).name
            candidate = SIM / (
                source
                if source.endswith("_test.go")
                else source.removesuffix(".go") + "_test.go"
            )
            if source.endswith(".md"):
                continue
            if source == "observer_equivocation.go":
                files.add(SIM / "observer_control_test.go")
            if source in {"partition_test.go", "simulation_test.go"}:
                broad = True
            elif source in SCENARIO_SOURCES or source == "scenarios.go":
                files.add(SIM / "simulation_test.go")
            elif candidate.is_file():
                files.add(candidate)
                if source == "concurrent_matrix.go":
                    files |= {
                        SIM / "history_race_test.go",
                        SIM / "local_processes_test.go",
                        SIM / "generated_groups_test.go",
                        SIM / "simulation_test.go",
                    }
                if source == "workload.go":
                    files |= {
                        SIM / "simulation_test.go",
                        SIM / "generated_groups_test.go",
                        SIM / "generated_team_test.go",
                    }
                mutation |= source == "mutation_test.go"
            else:
                broad = True
        elif path in {".github/workflows/simulation.yaml", "scripts/dst_plan.py"}:
            files |= {
                SIM / "partition_test.go",
                SIM / "restart_test.go",
                SIM / "generated_groups_test.go",
            }
        elif path.endswith("_test.go") and path.startswith(("app/", "pkg/")):
            # Dependency tests are run by native CI, not compiled into DST.
            continue
        elif path.endswith(".go") and path.startswith(("app/", "pkg/")):
            parts = Path(path).parts
            stem = Path(path).stem.removesuffix("_test")
            domain = None
            if path.startswith("app/"):
                if stem in {"secrets", "resolve"}:
                    domain = "secrets"
                elif stem.startswith(("history", "compact")):
                    domain = "history"
                elif stem in {"members", "upgrade"}:
                    domain = "members"
                elif stem.startswith(("init", "trust")):
                    domain = "trust"
                elif stem.startswith(("pull", "env", "switch")):
                    domain = "files"
                else:
                    broad = True
            elif parts[1] == "wsp":
                mutation = True
                if stem in {"chain", "control", "join"}:
                    domain = "members"
                elif stem in {"dag", "state"}:
                    domain = "merge"
                elif stem == "compaction":
                    domain = "history"
                elif stem.startswith(("checkpoint", "trust", "lock")):
                    domain = "trust"
                else:
                    broad = True
            elif parts[1] in {"clock", "merge", "identity"}:
                domain = parts[1]
                merge |= domain == "merge"
            elif parts[1] in {
                "age",
                "signing",
                "storage",
                "config",
                "bundle",
                "fsutil",
                "schema",
            }:
                broad = True
                mutation = True
            elif parts[1] == "auth":
                files.add(SIM / "session_http_test.go")
            elif parts[1] not in {"provider", "keystore", "process", "export"}:
                # Unknown application dependencies must not silently skip DST.
                broad = mutation = True
            if domain:
                files |= {
                    SIM / "team_incident_test.go",
                    SIM / "team_migration_test.go",
                    SIM / "generated_team_test.go",
                    SIM / "authority_attack_test.go",
                    SIM / "refounding_test.go",
                    SIM / "onboarding_test.go",
                    SIM / "local_processes_test.go",
                    SIM / "device_replacement_test.go",
                    SIM / "partial_keys_test.go",
                    SIM / "request_flood_test.go",
                    SIM / "metadata_flood_test.go",
                    SIM / "wire_attack_test.go",
                    SIM / "output_boundary_test.go",
                    SIM / "portable_config_test.go",
                    SIM / "contention_test.go",
                    SIM / "multi_workspace_test.go",
                    SIM / "git_worktrees_test.go",
                    SIM / "disaster_recovery_test.go",
                    SIM / "history_snapshot_test.go",
                    SIM / "larger_team_test.go",
                    SIM / "observer_equivocation_test.go",
                    SIM / "observer_control_test.go",
                    SIM / "first_contact_test.go",
                    SIM / "session_http_test.go",
                    SIM / "retained_observer_test.go",
                }
                mutation |= domain in {
                    "secrets",
                    "history",
                    "members",
                    "trust",
                    "merge",
                }
                scenarios = True
                files |= {SIM / (name + "_test.go") for name in DOMAINS[domain]}
    if broad:
        mutation = True
        files = set(SIM.glob("*_test.go"))
    tests = set().union(*(names(path) for path in files))
    if scenarios:
        tests.add("TestScenarios")
    # Each native lane runs mutations after its exploration command.
    tests.discard("TestOracleMutationExperiments")
    if files:
        tests |= {
            "TestSimulation",
            "TestSimulationSmoke",
            "TestFullSignatureAttackSeedRegressionSmoke",
            "TestStateSignatureAttackSmoke",
            "TestEveryAppOperationHasSimulationDriver",
        }
    return {
        "run": bool(tests or mutation or merge),
        "mode": "full" if full else "incremental",
        "tests": "^(" + "|".join(sorted(tests)) + ")$" if tests else "^$",
        "mutation": mutation,
        "merge": merge,
    }


def changed(event: dict) -> list[str]:
    before = event.get("before", "")
    head = event.get("after") or "HEAD"
    if not before or set(before) == {"0"}:
        branch = event["repository"]["default_branch"]
        before = subprocess.check_output(
            ["git", "merge-base", "HEAD", "refs/remotes/origin/" + branch],
            cwd=ROOT,
            text=True,
        ).strip()
    try:
        data = subprocess.check_output(
            ["git", "diff", "--name-only", "-z", before, head], cwd=ROOT
        )
    except subprocess.CalledProcessError:
        # Unavailable old commits must broaden coverage, never silently skip it.
        return ["go.mod"]
    return [path for path in data.decode().split("\0") if path]


def main() -> None:
    event = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text())
    full = os.environ["GITHUB_EVENT_NAME"] in {"schedule", "workflow_dispatch"}
    paths = [] if full else changed(event)
    plan = select(paths, full)
    plan["platforms"] = json.dumps(
        platforms(
            plan["mode"],
            os.environ["GITHUB_EVENT_NAME"],
            datetime.now(UTC).date(),
        ),
        separators=(",", ":"),
    )
    with Path(os.environ["GITHUB_OUTPUT"]).open("a") as output:
        for key, value in plan.items():
            print(
                f"{key}={json.dumps(value) if isinstance(value, bool) else value}",
                file=output,
            )
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with Path(summary).open("a") as output:
            print("DST mode: " + plan["mode"], file=output)
            print("Platforms: " + plan["platforms"], file=output)
            print(
                "\nChanged paths:\n" + "\n".join("- " + path for path in paths),
                file=output,
            )
            print("\nSelected tests: `" + plan["tests"] + "`", file=output)


if __name__ == "__main__":
    main()
