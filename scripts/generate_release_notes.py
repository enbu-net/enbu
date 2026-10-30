#!/usr/bin/env python3
"""Generate GitHub release notes with a table of downloadable binaries."""

from __future__ import annotations

import argparse
import os
import re
import sys
from collections.abc import Mapping
from pathlib import Path
from urllib.parse import quote

AssetKey = tuple[str, str]

OS_LABELS = {
    "darwin": "macOS",
    "linux": "Linux",
    "windows": "Windows",
}
ARCH_LABELS = {
    "amd64": "x64",
    "arm64": "arm64",
}
OS_ORDER = {"darwin": 0, "linux": 1, "windows": 2}
ARCH_ORDER = {"amd64": 0, "arm64": 1}


class ReleaseNotesError(ValueError):
    """Raised when release notes cannot be generated safely."""


# Each kind of asset is a column of the download table, in this order.
ASSET_KINDS = (
    ("cli", "CLI", "enbu", r"tar\.gz|zip"),
    ("desktop", "Desktop", "enbu-desktop", r"tar\.gz|zip|dmg"),
    ("vscode", "VS Code", "enbu-vscode", r"vsix"),
)

Assets = dict[str, dict[AssetKey, str]]


def collect_assets(assets_dir: Path, tag: str) -> Assets:
    """Return release assets by kind, keyed by OS and architecture."""
    if not assets_dir.is_dir():
        raise ReleaseNotesError(f"release assets directory not found: {assets_dir}")

    escaped_tag = re.escape(tag)
    patterns = [
        (
            kind,
            label,
            re.compile(
                rf"^{re.escape(prefix)}_{escaped_tag}_([^_]+)_([^_.]+)\.(?:{extensions})$"
            ),
        )
        for kind, label, prefix, extensions in ASSET_KINDS
    ]
    assets: Assets = {kind: {} for kind, *_ in ASSET_KINDS}

    for path in sorted(assets_dir.iterdir()):
        if not path.is_file():
            continue

        for kind, label, pattern in patterns:
            match = pattern.fullmatch(path.name)
            if match is None:
                continue
            key = match.group(1), match.group(2)
            if existing := assets[kind].get(key):
                raise ReleaseNotesError(
                    f"multiple {label} assets found for {key[0]}/{key[1]}: "
                    f"{existing}, {path.name}"
                )
            assets[kind][key] = path.name
            break

    if not any(assets.values()):
        raise ReleaseNotesError(
            f"no release assets found in {assets_dir} for tag {tag}"
        )

    return assets


def asset_url(repository: str, tag: str, name: str) -> str:
    """Build a GitHub download URL with safely encoded path components."""
    repository_path = quote(repository, safe="/")
    return (
        f"https://github.com/{repository_path}/releases/download/"
        f"{quote(tag, safe='')}/{quote(name, safe='')}"
    )


def asset_link(repository: str, tag: str, name: str | None) -> str:
    if name is None:
        return "—"
    return f"[`{name}`]({asset_url(repository, tag, name)})"


def asset_sort_key(key: AssetKey) -> tuple[int, str, int, str]:
    os_name, arch = key
    return (
        OS_ORDER.get(os_name, len(OS_ORDER)),
        os_name,
        ARCH_ORDER.get(arch, len(ARCH_ORDER)),
        arch,
    )


def render_release_notes(
    repository: str,
    tag: str,
    assets: Mapping[str, Mapping[AssetKey, str]],
    generated_notes: str = "",
) -> str:
    """Render the download table followed by GitHub-generated notes."""
    kinds = [(kind, assets.get(kind, {})) for kind, *_ in ASSET_KINDS]
    keys = sorted(
        set().union(*(by_key.keys() for _, by_key in kinds)), key=asset_sort_key
    )
    labels = [label for _, label, *_ in ASSET_KINDS]
    lines = [
        "## Downloads",
        "",
        "| OS | Arch | " + " | ".join(labels) + " |",
        "| --- | --- | " + " | ".join("---" for _ in labels) + " |",
    ]

    for os_name, arch in keys:
        key = os_name, arch
        links = " | ".join(
            asset_link(repository, tag, by_key.get(key)) for _, by_key in kinds
        )
        lines.append(
            f"| {OS_LABELS.get(os_name, os_name)} | {ARCH_LABELS.get(arch, arch)} | {links} |"
        )

    if generated_notes.strip():
        lines.extend(("", generated_notes.strip()))

    return "\n".join(lines) + "\n"


def env_default(name: str) -> str | None:
    value = os.environ.get(name)
    return value if value else None


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--assets-dir",
        type=Path,
        default=Path(os.environ.get("RELEASE_ASSETS_DIR", "release-assets")),
    )
    parser.add_argument("--repository", default=env_default("GITHUB_REPOSITORY"))
    parser.add_argument("--tag", default=env_default("GITHUB_REF_NAME"))
    parser.add_argument(
        "--generated-notes",
        type=Path,
        default=(
            Path(value)
            if (value := env_default("GENERATED_NOTES_FILE")) is not None
            else None
        ),
    )
    args = parser.parse_args(argv)
    if args.repository is None:
        parser.error("--repository or GITHUB_REPOSITORY is required")
    if args.tag is None:
        parser.error("--tag or GITHUB_REF_NAME is required")
    return args


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        assets = collect_assets(args.assets_dir, args.tag)
        generated_notes = (
            args.generated_notes.read_text(encoding="utf-8")
            if args.generated_notes is not None
            else ""
        )
        sys.stdout.write(
            render_release_notes(
                args.repository,
                args.tag,
                assets,
                generated_notes,
            )
        )
    except (OSError, ReleaseNotesError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
