"""SAN-765: cross-SDK allow-disposition conformance (Python side).

Drives the http + subprocess interceptors with an allowed (can_execute) decision in enforce mode
and asserts the emitted receipt matches the shared protocol fixture
(spec/fixtures/multi-surface-vectors.json -> allow_disposition_vectors) AND that the action
executed. The sanna-ts suite asserts the SAME vector.

Per spec Section 7.3 an authority-only interceptor never runs reasoning checks, so an allowed
action emits assurance="partial" (NOT "full"). action_hash is not pinned (the executed action's
output hash is environment-dependent) and is therefore not asserted -- the fixture's not_pinned
list is honored.
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
_ALLOW_VECTORS = json.loads(SPEC_VECTORS.read_text())["allow_disposition_vectors"]


def _vector(surface: str) -> dict:
    return next(v for v in _ALLOW_VECTORS if v["surface"] == surface)


class CaptureSink(ReceiptSink):
    def __init__(self) -> None:
        self.receipts: list[dict] = []

    def store(self, receipt: dict) -> SinkResult:
        self.receipts.append(receipt)
        return SinkResult(stored=1)

    def invocation(self) -> list[dict]:
        return [r for r in self.receipts if r.get("event_type") != "session_manifest"]


def _mock_response(status_code: int = 200, content: bytes = b'{"ok":true}') -> MagicMock:
    """Minimal stand-in for a requests.Response so the allowed path can compute action_hash
    without a real network call (mirrors tests/test_http_interceptor.py::_mock_response)."""
    resp = MagicMock()
    resp.status_code = status_code
    resp.content = content
    resp.headers = {"Content-Type": "application/json"}
    resp.text = content.decode("utf-8")
    return resp


def _assert_matches(receipt: dict, expected: dict) -> None:
    assert receipt["event_type"] == expected["event_type"]
    assert receipt["enforcement"]["action"] == expected["enforcement_action"]
    assert receipt["enforcement"]["enforcement_mode"] == expected["enforcement_mode"]
    assert receipt["status"] == expected["status"]
    assert receipt["enforcement_surface"] == expected["enforcement_surface"]
    assert receipt["invariants_scope"] == expected["invariants_scope"]
    assert receipt["assurance"] == expected["assurance"]
    # action_hash is not pinned for allowed actions (output hash is environment-dependent);
    # honor the fixture's not_pinned list rather than asserting a value.
    if "action_hash" in expected:
        assert receipt["action_hash"] == expected["action_hash"]


# Mock-isolation: save the genuine original before overwriting _originals, and restore it before
# unpatch_http reads _originals (mirrors tests/test_escalate_conformance.py's cleanup pattern).
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
    assert isinstance(_ALLOW_VECTORS, list)
    assert sorted(v["surface"] for v in _ALLOW_VECTORS) == ["cli", "http"]
    # Guard the inverted-divergence premise: both allowed surfaces must pin assurance="partial".
    assert all(v["expected"]["assurance"] == "partial" for v in _ALLOW_VECTORS)


def test_cli_allowed_executes_and_matches_vector():
    vec = _vector("cli")
    sink = CaptureSink()
    patch_subprocess(constitution_path=CLI_CONSTITUTION, sink=sink, agent_id="test-agent", mode="enforce")
    sink.receipts.clear()  # drop session_manifest
    # echo is can_execute in cli-test.yaml -> allowed -> the real (harmless) echo executes.
    result = subprocess.run(["echo", "hello"], capture_output=True, text=True)
    assert result.returncode == 0  # the action executed
    inv = sink.invocation()
    assert len(inv) == 1
    _assert_matches(inv[0], vec["expected"])


def test_http_allowed_executes_and_matches_vector():
    requests = pytest.importorskip("requests")
    vec = _vector("http")
    sink = CaptureSink()
    patch_http(constitution_path=API_CONSTITUTION, sink=sink, agent_id="test-agent", mode="enforce")
    sink.receipts.clear()  # drop session_manifest
    from sanna.interceptors import http_interceptor
    # Replace the saved original with a mock: the allowed path DOES call the original, so the mock
    # must be invoked (proving execution) -- but no real network call is made.
    if "requests.get" in http_interceptor._originals:
        _saved_http_originals["requests.get"] = http_interceptor._originals["requests.get"]
    mock = MagicMock(return_value=_mock_response())
    http_interceptor._originals["requests.get"] = mock
    # api.example.com/* is can_execute (api-001) -> allowed.
    requests.get("https://api.example.com/data")
    mock.assert_called_once()  # the allowed path executed the original
    inv = sink.invocation()
    assert len(inv) == 1
    _assert_matches(inv[0], vec["expected"])
