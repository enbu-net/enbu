"""Collect isolated Tobari reports and merge them without losing test binaries."""

import argparse
import json
import os
import shutil
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUTPUT = ROOT / ".tmp" / "coverage"
MODULE = "github.com/enbu-net/enbu"
COVERPKG = ",".join(
    [
        MODULE,
        *(
            f"{MODULE}/{p}/..."
            for p in ("app", "cli", "pkg", "desktop", "tui", "tools")
        ),
    ]
)


def packages(env: dict[str, str]) -> list[str]:
    result = subprocess.run(
        [
            "go",
            "list",
            "-f",
            "{{if or .TestGoFiles .XTestGoFiles}}{{.ImportPath}}{{end}}",
            "./...",
        ],
        cwd=ROOT,
        env=env,
        text=True,
        capture_output=True,
        check=True,
    )
    return sorted(p for p in result.stdout.splitlines() if p)


def report_paths(directory: Path) -> list[Path]:
    return sorted(directory.rglob("*.json"))


def merge(directory: Path, destination: Path) -> None:
    reports = report_paths(directory)
    if not reports:
        raise RuntimeError(f"No coverage reports in {directory}")
    if len(reports) == 1:
        shutil.copyfile(reports[0], destination)
        return
    subprocess.run(
        ["tobari", "merge", "json", "-o", str(destination), *map(str, reports)],
        cwd=ROOT,
        check=True,
    )


def collect(suite: str) -> int:
    for stale in (
        OUTPUT / f"{suite}.json",
        OUTPUT / "merged.json",
        OUTPUT / "coverage.html",
        OUTPUT / "coverage.out",
    ):
        stale.unlink(missing_ok=True)
    output = OUTPUT / suite
    if output.exists():
        shutil.rmtree(output)
    output.mkdir(parents=True)
    tags = "enbucoverage,fixture"
    if suite == "scenario":
        tags += ",scenario"
    if suite == "identity":
        tags += ",identitye2e"
    env = os.environ.copy()
    # Tobari v0.13.0 static analysis loses build tags for test-only packages.
    # Tagged parent suites retain per-test hits with passed-blocks-only.
    env["GOFLAGS"] = (
        subprocess.check_output(
            [
                "tobari",
                "flags",
                f"-tags={tags}",
                *(["-passed-blocks-only"] if suite in ("scenario", "identity") else []),
            ],
            text=True,
        ).strip()
        + f" -coverpkg={COVERPKG}"
    )
    env["ENBU_TEST_COVERAGE_DIR"] = str(output / "processes")

    targets = packages(env) if suite == "unit" else [f"{MODULE}/test"]
    if suite == "identity":
        targets = [f"{MODULE}/test/identitye2e"]
    failed = False
    if suite == "e2e":
        failed = (
            subprocess.run(["task", "cli/test/e2e"], cwd=ROOT, env=env).returncode != 0
        )
    else:
        for package in targets:
            package_env = env | {
                "TOBARI_COVERDIR": str(
                    output / (package.removeprefix(MODULE).strip("/") or "main")
                ),
            }
            # The parent test name is supplied by the Identity CLI harness.
            result = subprocess.run(
                ["go", "test", "-count=1", "-shuffle=on", "-race", package],
                cwd=ROOT,
                env=package_env,
            )
            failed = failed or result.returncode != 0
            report = Path(package_env["TOBARI_COVERDIR"]) / "tobari" / "tobari.json"
            if not report.is_file():
                failed = True
                print(f"Missing package report: {package}", flush=True)
    if suite in ("e2e", "identity") and not report_paths(output / "processes"):
        failed = True
        print(f"Missing child CLI reports: {suite}", flush=True)
    merge(output, OUTPUT / f"{suite}.json")
    return int(failed)


def summarize(report: Path) -> None:
    data = json.loads(report.read_text())
    blocks = data["metadata"]["all"]
    counts = data["allcounts"]
    total = sum(block[5] for block in blocks)
    covered = sum(
        block[5] for block, count in zip(blocks, counts, strict=True) if count
    )
    print(
        f"{covered}/{total} statements; {len(data['counts'])} named scopes", flush=True
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "suite", choices=("unit", "scenario", "identity", "e2e", "report")
    )
    suite = parser.parse_args().suite
    if suite != "report":
        return collect(suite)
    reports = [
        OUTPUT / f"{suite}.json" for suite in ("unit", "scenario", "identity", "e2e")
    ]
    missing = [str(p) for p in reports if not p.is_file()]
    if missing:
        raise RuntimeError(f"Missing suite reports: {missing}")
    subprocess.run(
        [
            "tobari",
            "merge",
            "json",
            "-o",
            str(OUTPUT / "merged.json"),
            *map(str, reports),
        ],
        cwd=ROOT,
        check=True,
    )
    subprocess.run(
        [
            "tobari",
            "html",
            "-o",
            str(OUTPUT / "coverage.html"),
            str(OUTPUT / "merged.json"),
        ],
        cwd=ROOT,
        check=True,
    )
    subprocess.run(
        [
            "tobari",
            "convert",
            "-o",
            str(OUTPUT / "coverage.out"),
            str(OUTPUT / "merged.json"),
        ],
        cwd=ROOT,
        check=True,
    )
    summarize(OUTPUT / "merged.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
