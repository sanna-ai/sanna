"""SAN-745: cross-SDK escalate-disposition conformance (Python side).

Drives the http + subprocess interceptors with a must_escalate decision in enforce mode and
asserts the emitted receipt matches the shared protocol fixture
(spec/fixtures/multi-surface-vectors.json -> escalate_disposition_vectors) AND that the action
did not execute. The sanna-ts suite asserts the SAME vector (SAN-745 PR3a).
"""
from __future__ import annotations

import json
import subprocess
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from sanna.interceptors import patch_subprocess, unpatch_subprocess, patch_http, unpatch_http
from sanna.sinks.sink import ReceiptSink, SinkResult

CONSTITUTIONS_DIR = Path(__file__).parent / "constitutions"
CLI_CONSTITUTION = str(CONSTITUTIONS_DIR / "cli-test.yaml")
API_CONSTITUTION = str(CONSTITUTIONS_DIR / "api-test.yaml")
SPEC_VECTORS = Path(__file__).parent.parent / "spec" / "fixtures" / "multi-surface-vectors.json"

# KeyError at collection time if the submodule bump did not take -> loud failure, never a silent skip.
_DISPOSITION_VECTORS = json.loads(SPEC_VECTORS.read_text())["escalate_disposition_vectors"]


def _vector(surface: str) -> dict:
    return next(v for v in _DISPOSITION_VECTORS if v["surface"] == surface)


class CaptureSink(ReceiptSink):
    def __init__(self) -> None:
        self.receipts: list[dict] = []

    def store(self, receipt: dict) -> SinkResult:
        self.receipts.append(receipt)
        return SinkResult(stored=1)

    def invocation(self) -> list[dict]:
        return [r for r in self.receipts if r.get("event_type") != "session_manifest"]


def _assert_matches(receipt: dict, expected: dict) -> None:
    assert receipt["event_type"] == expected["event_type"]
    assert receipt["enforcement"]["action"] == expected["enforcement_action"]
    assert receipt["enforcement"]["enforcement_mode"] == expected["enforcement_mode"]
    assert receipt["status"] == expected["status"]
    assert receipt["enforcement_surface"] == expected["enforcement_surface"]
    assert receipt["invariants_scope"] == expected["invariants_scope"]
    assert receipt["action_hash"] == expected["action_hash"]
    assert receipt["assurance"] == expected["assurance"]


# Mock-isolation: save the genuine original before overwriting _originals, and restore it before
# unpatch_http reads _originals (mirrors tests/test_http_interceptor.py's proven cleanup pattern).
_saved_http_originals: dict = {}


@pytest.fixture(autouse=True)
def _cleanup():
    yield
    from sanna.interceptors import http_interceptor
    for key, real_fn in _saved_http_originals.items():
        if key in http_interceptor._originals:
            http_interceptor._originals[key] = real_fn
    _saved_http_originals.clear()
    unpatch_http()
    unpatch_subprocess()


def test_fixture_present_with_cli_and_http_vectors():
    # Fails loudly if the submodule bump did not take.
    assert isinstance(_DISPOSITION_VECTORS, list)
    assert sorted(v["surface"] for v in _DISPOSITION_VECTORS) == ["cli", "http"]


def test_cli_must_escalate_blocks_and_matches_vector():
    vec = _vector("cli")
    sink = CaptureSink()
    patch_subprocess(constitution_path=CLI_CONSTITUTION, sink=sink, agent_id="test-agent", mode="enforce")
    sink.receipts.clear()  # drop session_manifest
    with pytest.raises(PermissionError, match="Escalation required"):
        subprocess.run(["docker", "run", "nginx"])
    inv = sink.invocation()
    assert len(inv) == 1
    _assert_matches(inv[0], vec["expected"])


def test_http_must_escalate_blocks_and_matches_vector():
    requests = pytest.importorskip("requests")
    vec = _vector("http")
    sink = CaptureSink()
    patch_http(constitution_path=API_CONSTITUTION, sink=sink, agent_id="test-agent", mode="enforce")
    sink.receipts.clear()  # drop session_manifest
    from sanna.interceptors import http_interceptor
    # Replace the saved original with a mock so a regression cannot make a real network call;
    # the escalate path raises before the original is invoked, so the mock must NOT be called.
    if "requests.post" in http_interceptor._originals:
        _saved_http_originals["requests.post"] = http_interceptor._originals["requests.post"]
    mock = MagicMock()
    http_interceptor._originals["requests.post"] = mock
    with pytest.raises(PermissionError, match="Escalation required"):
        requests.post("https://api.stripe.com/v1/charges", json={"amount": 100})
    mock.assert_not_called()
    inv = sink.invocation()
    assert len(inv) == 1
    _assert_matches(inv[0], vec["expected"])
