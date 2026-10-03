"""Runs every YAML case in tests/cases/ through the full gateway (in-process, no network, no models)."""

from __future__ import annotations

import asyncio

import pytest

from bouncer.selftest import CaseRunner, load_cases

CASES = load_cases()


@pytest.fixture(scope="module")
def runner(tmp_path_factory: pytest.TempPathFactory) -> CaseRunner:
    return CaseRunner(workdir=tmp_path_factory.mktemp("cases"))


@pytest.mark.parametrize("case", CASES, ids=[c["id"] for c in CASES])
def test_case(case: dict, runner: CaseRunner, record_property) -> None:  # noqa: ANN001
    result = asyncio.run(runner.run_case(case))
    record_property("control", result.control)
    record_property("kind", result.kind)
    record_property("file", result.file)
    assert result.passed, "\n".join(result.failures)
