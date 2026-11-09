from pathlib import Path

import pytest

import formal

MODELS = {"ControlDAG", "StateDAG", "MemberChange", "WriteRetry", "Founding"}


def config(tmp_path: Path, name: str, text: str) -> formal.Config:
    path = tmp_path / name
    path.write_text(text)
    return formal.parse_config("M", path)


def test_parse_config_reads_expectation_and_trace(tmp_path):
    c = config(
        tmp_path,
        "M_bug.cfg",
        "\\* Mutant: x\n\\* expect: violation GEN_1\n\\* trace: m-bug.txt\nINVARIANT GEN_1\n",
    )
    assert c.expect == "GEN_1"
    assert c.trace == "m-bug.txt"
    assert not c.large


def test_parse_config_without_expectation_must_hold(tmp_path):
    c = config(tmp_path, "M.large.cfg", "INVARIANT GEN_1\n")
    assert c.expect is None
    assert c.large


@pytest.mark.parametrize(
    ("expect", "output", "ok"),
    [
        (None, formal.PASSED, True),
        (None, "Error: Invariant GEN_1 is violated.\n", False),
        (None, "Error: TLC threw an unexpected exception.\n", False),
        ("GEN_1", "Error: Invariant GEN_1 is violated.\n", True),
        ("GEN_3", "Error: Action property GEN_3 is violated.\n", True),
        ("FORK_3", "Error: Temporal property FORK_3 was violated.\n", True),
        ("GEN_1", "Error: Invariant GEN_2 is violated.\n", False),
        ("GEN_1", formal.PASSED, False),
    ],
)
def test_verdict(tmp_path, expect, output, ok):
    text = f"\\* expect: violation {expect}\n" if expect else ""
    c = config(tmp_path, "M_x.cfg", text)
    assert (formal.verdict(c, output) is None) == ok


def test_counterexample_keeps_the_violation_and_behavior():
    output = "\n".join(
        [
            "Starting...",
            "Error: Invariant GEN_1 is violated.",
            "Error: The behavior up to this point is:",
            "State 1: <Initial predicate>",
            "/\\ x = 0",
            "",
            "12 states generated, 10 distinct states found, 0 states left on queue.",
            "Finished in 00s",
        ]
    )
    trace = formal.counterexample(output)
    assert trace.startswith("Error: Invariant GEN_1 is violated.")
    assert "State 1" in trace
    assert "states generated" not in trace


def test_every_model_has_small_large_and_mutants():
    configs = formal.discover()
    assert {c.model for c in configs} == MODELS
    for model in MODELS:
        mine = [c for c in configs if c.model == model]
        names = {c.path.name for c in mine}
        assert f"{model}.cfg" in names
        assert f"{model}.large.cfg" in names
        mutants = [c for c in mine if c.expect and "_example" not in c.path.name]
        mutants = [c for c in mutants if "_finding" not in c.path.name]
        assert len(mutants) >= 5, model
        for c in mine:
            base = c.path.name in {f"{model}.cfg", f"{model}.large.cfg"}
            assert base == (c.expect is None), c.path.name


def test_every_expected_violation_is_a_checked_property():
    for c in formal.discover():
        if c.expect:
            text = c.path.read_text()
            assert f" {c.expect}" in text.split("expect:")[1].split("\n", 1)[1], (
                c.path.name
            )


def test_select_filters_by_size_and_model():
    configs = formal.discover()
    small = formal.select(configs, False, ["Founding"])
    assert small and all(c.model == "Founding" and not c.large for c in small)
    large = formal.select(configs, True, [])
    assert {c.model for c in large} == MODELS
