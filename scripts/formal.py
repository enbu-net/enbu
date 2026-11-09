"""Run the TLA+ models in spec/tla with TLC and check each config's verdict.

Every model directory holds <Model>.tla and its configs:

- <Model>.cfg, the small config: every property must hold.
- <Model>.large.cfg, the large config (nightly): every property must hold.
- <Model>_<name>.cfg, a mutant, example or finding: it names the property
  TLC must report violated in a "\\* expect: violation <Property>" line.

A config with a "\\* trace: <file>" line also writes TLC's counterexample to
spec/tla/traces/<file> when run with --write-traces.
"""

import argparse
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SPEC = ROOT / "spec" / "tla"
TRACES = SPEC / "traces"

EXPECT = re.compile(r"^\\\*\s*expect:\s*violation\s+(\w+)\s*$", re.M)
TRACE = re.compile(r"^\\\*\s*trace:\s*(\S+)\s*$", re.M)
VIOLATED = re.compile(
    r"^Error: (?:Invariant|Action property|Temporal property) (\w+) (?:is|was) violated",
    re.M,
)
PASSED = "Model checking completed. No error has been found."


@dataclass(frozen=True)
class Config:
    model: str
    path: Path
    expect: str | None  # the property TLC must report violated, or None
    trace: str | None
    large: bool


def parse_config(model: str, path: Path) -> Config:
    text = path.read_text()
    expect = EXPECT.search(text)
    trace = TRACE.search(text)
    return Config(
        model=model,
        path=path,
        expect=expect.group(1) if expect else None,
        trace=trace.group(1) if trace else None,
        large=path.name.endswith(".large.cfg"),
    )


def discover(spec: Path = SPEC) -> list[Config]:
    out = []
    for module in sorted(spec.glob("*/*.tla")):
        model = module.stem
        if module.parent.name != model:
            continue
        for cfg in sorted(module.parent.glob(f"{model}*.cfg")):
            out.append(parse_config(model, cfg))
    return out


def select(configs: list[Config], large: bool, models: list[str]) -> list[Config]:
    return [
        c for c in configs if c.large == large and (not models or c.model in models)
    ]


def verdict(config: Config, output: str) -> str | None:
    """Return why the run disagrees with the config's expectation, or None."""
    violated = VIOLATED.findall(output)
    if config.expect is None:
        if violated:
            return f"expected every property to hold, but {', '.join(violated)} was violated"
        if PASSED not in output:
            return "TLC did not complete the check"
        return None
    if config.expect not in violated:
        found = ", ".join(violated) or "no violation"
        return f"expected {config.expect} to be violated, got {found}"
    return None


def counterexample(output: str) -> str:
    """The violation and the behavior TLC printed, without its progress noise."""
    lines = output.splitlines()
    start = next((i for i, line in enumerate(lines) if VIOLATED.match(line)), 0)
    end = next(
        (
            i
            for i in range(start, len(lines))
            if re.match(r"^\d+ states generated", lines[i])
        ),
        len(lines),
    )
    return "\n".join(lines[start:end]).rstrip() + "\n"


def tlc() -> list[str]:
    exe = os.environ.get("TLC", "tlc")
    if shutil.which(exe) is None:
        sys.exit(f"{exe} not found; install it with 'aqua i' (yashikota/tlc-static)")
    return [exe]


def run(config: Config, workers: str) -> tuple[str, float]:
    with tempfile.TemporaryDirectory(prefix="tlc-") as meta:
        cmd = tlc() + [
            "-workers",
            workers,
            "-nowarning",
            "-noGenerateSpecTE",
            "-cleanup",
            "-metadir",
            meta,
            "-config",
            config.path.name,
            f"{config.model}.tla",
        ]
        start = time.monotonic()
        proc = subprocess.run(
            cmd, cwd=config.path.parent, capture_output=True, text=True, check=False
        )
        return proc.stdout + proc.stderr, time.monotonic() - start


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--large", action="store_true", help="run the large configs instead"
    )
    parser.add_argument(
        "--model", action="append", default=[], help="only this model (repeatable)"
    )
    parser.add_argument("--workers", default="auto")
    parser.add_argument(
        "--write-traces",
        action="store_true",
        help="save the counterexample of configs with a trace line",
    )
    args = parser.parse_args(argv)

    # One worker makes the saved counterexamples reproducible.
    workers = "1" if args.write_traces else args.workers
    configs = select(discover(), args.large, args.model)
    if not configs:
        print("no configs selected", file=sys.stderr)
        return 1
    failed = 0
    for config in configs:
        output, seconds = run(config, workers)
        problem = verdict(config, output)
        want = f"violates {config.expect}" if config.expect else "holds"
        status = "ok  " if problem is None else "FAIL"
        print(
            f"{status} {config.path.relative_to(SPEC)} ({want}) {seconds:.1f}s",
            flush=True,
        )
        if problem is not None:
            failed += 1
            print(f"     {problem}\n{output}", file=sys.stderr)
        elif args.write_traces and config.trace:
            TRACES.mkdir(exist_ok=True)
            (TRACES / config.trace).write_text(
                f"# {config.path.relative_to(SPEC)}: TLC counterexample\n\n"
                + counterexample(output)
            )
    print(f"{len(configs) - failed}/{len(configs)} configs as expected")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
