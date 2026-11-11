"""Select which CI jobs a commit needs from the paths it changes.

`code` is false only when every changed path is documentation, so a docs-only
change skips the builds and tests. Scheduled and manual runs on main run
everything. The reproducible-build comparison is not part of CI: the release
workflow runs it, and its dry run checks it before a release.
"""

import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# Root-level Markdown only: nested READMEs can be test or package inputs
# (test/simulation/README.md is read by a test, vscode/README.md is packaged).
DOCS = re.compile(
    r"[^/]+\.md|docs/.*|LICENSE|\.coderabbit\.yaml|\.github/pull_request_template\.md"
)


def select(paths: list[str]) -> dict[str, bool]:
    return {
        "code": any(not DOCS.fullmatch(path) for path in paths),
    }


def changed() -> list[str]:
    # actions/checkout of a pull request checks out its merge commit, whose
    # first parent is the base branch tip: the diff is what the merge brings.
    try:
        data = subprocess.check_output(
            ["git", "diff", "--name-only", "-z", "HEAD^1", "HEAD"], cwd=ROOT
        )
    except subprocess.CalledProcessError:
        # An unreadable diff must run everything, never silently skip it.
        return ["go.mod"]
    return [path for path in data.decode().split("\0") if path]


def main() -> None:
    if os.environ.get("GITHUB_EVENT_NAME") == "pull_request":
        paths = changed()
        plan = select(paths)
    else:
        paths = []
        plan = {"code": True}
    lines = [f"{key}={'true' if value else 'false'}" for key, value in plan.items()]
    output = os.environ.get("GITHUB_OUTPUT")
    if output:
        with Path(output).open("a") as f:
            print("\n".join(lines), file=f)
    else:
        print("\n".join(lines))
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with Path(summary).open("a") as f:
            print("\n".join("- " + line for line in lines), file=f)
            if paths:
                print("\nChanged paths:\n" + "\n".join("- " + p for p in paths), file=f)


if __name__ == "__main__":
    sys.exit(main())
