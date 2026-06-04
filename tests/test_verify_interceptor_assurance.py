"""SAN-765 / spec Section 7.3: verifier rejects authority-only Receipt Triad receipts
whose assurance != "partial".

Drives a real allowed subprocess action to emit a schema-valid authority_only receipt,
then checks:
  - partial (correct): 7.3 error absent
  - full   (incorrect): 7.3 error present, result invalid
"""
from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from sanna.interceptors import patch_subprocess, unpatch_subprocess
from sanna.sinks.sink import ReceiptSink, SinkResult
from sanna.verify import load_schema, verify_receipt

CONSTITUTIONS_DIR = Path(__file__).parent / "constitutions"
CLI_CONSTITUTION = str(CONSTITUTIONS_DIR / "cli-test.yaml")

_MSG_73 = (
    "Authority-only receipt (invariants_scope=authority_only) with a Receipt Triad "
    "must have assurance='partial' per spec Section 7.3 (no reasoning checks ran)."
)

SCHEMA = load_schema()


class CaptureSink(ReceiptSink):
    def __init__(self) -> None:
        self.receipts: list[dict] = []

    def store(self, receipt: dict) -> SinkResult:
        self.receipts.append(receipt)
        return SinkResult(stored=1)

    def invocation(self) -> list[dict]:
        return [r for r in self.receipts if r.get("event_type") != "session_manifest"]


@pytest.fixture(autouse=True)
def _cleanup():
    yield
    unpatch_subprocess()


@pytest.fixture
def allowed_receipt() -> dict:
    sink = CaptureSink()
    patch_subprocess(constitution_path=CLI_CONSTITUTION, sink=sink, agent_id="test-agent", mode="enforce")
    sink.receipts.clear()  # drop session_manifest
    subprocess.run(["echo", "hello"])
    inv = sink.invocation()
    assert len(inv) == 1, f"expected 1 invocation receipt, got {len(inv)}"
    receipt = inv[0]
    assert receipt.get("invariants_scope") == "authority_only", "receipt must be authority_only"
    assert receipt.get("assurance") == "partial", "interceptor must emit assurance=partial"
    assert any(
        isinstance(receipt.get(h), str) for h in ("input_hash", "reasoning_hash", "action_hash")
    ), "receipt must carry at least one triad hash"
    return receipt


def test_partial_assurance_passes_73_rule(allowed_receipt):
    vr = verify_receipt(allowed_receipt, SCHEMA)
    assert _MSG_73 not in vr.errors


def test_full_assurance_fails_73_rule(allowed_receipt):
    receipt_full = {**allowed_receipt, "assurance": "full"}
    vr = verify_receipt(receipt_full, SCHEMA)
    assert _MSG_73 in vr.errors
    assert vr.valid is False
