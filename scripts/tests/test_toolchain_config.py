"""Keep the tool versions used by local development and CI consistent."""

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def aqua_packages():
    return re.findall(r"^- name: (.+)$", (ROOT / "aqua.yaml").read_text(), re.MULTILINE)


def test_aqua_has_no_duplicate_packages():
    names = [package.rsplit("@", 1)[0] for package in aqua_packages()]
    assert len(names) == len(set(names))


def test_pnpm_version_matches_aqua_and_has_one_frontend_pin():
    package = json.loads((ROOT / "web/package.json").read_text())
    pnpm_version = package["packageManager"].removeprefix("pnpm@")
    assert f"pnpm/pnpm@v{pnpm_version}" in aqua_packages()
    assert "packageManager" not in package.get("devEngines", {})
