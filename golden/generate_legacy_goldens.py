#!/usr/bin/env python3
"""Generate cross-cv-level golden receipt fixtures (SAN-533).

Produces deterministic golden receipts at cv=5, 6, 7, 8, 10 (one PASS
scenario + one tampered variant per cv). Existing cv=9 goldens in
golden/receipts/0NN_*.json are kept as-is for CV9_LEGACY-codepath
coverage in verify.py.

Usage:
    python golden/generate_legacy_goldens.py

Each fixture uses sanna.fingerprint.compute_fingerprints (SAN-524
centralized cv-aware formula). The SDK emits at the latest cv level
(currently cv=10); older cv levels are hand-crafted with the
cv-appropriate field set.

Naming convention:
    v{cv}_pass_simple.json    -- PASS scenario at cv level
    v{cv}_tampered.json       -- same scenario tampered post-fingerprint

Tamper mechanism: outputs.response is mutated post-fingerprint while
output_hash is left at the original value. The verifier detects the
mismatch when it recomputes hash_obj(outputs) and compares to the
stored output_hash field.

Cross-references:
    SAN-533 (this ticket), SAN-524 (compute_fingerprints centralization),
    SAN-540 (follow-up to refactor golden/generate_golden.py to the same
    pattern; tracks the cv=9 inline-formula latent gap).
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from sanna.fingerprint import compute_fingerprints
from sanna.hashing import hash_obj

OUT = Path(__file__).resolve().parent / "receipts"

# spec_version + tool_version per cv. cv=6 + cv=8 confirmed from archive
# inspection (archive/pre-v1.3 and archive/v1.3). cv=5 / 7 / 10 derived:
# cv=10 from current SDK constants in receipt.py. Empirical verification
# via sanna-verify in Phase 4 confirms these are accepted.
CV_VERSION_MAP = {
    5:  {"spec_version": "1.0", "tool_version": "1.0.0"},
    6:  {"spec_version": "1.1", "tool_version": "1.0.0"},
    7:  {"spec_version": "1.2", "tool_version": "1.1.0"},
    8:  {"spec_version": "1.3", "tool_version": "1.1.1"},
    10: {"spec_version": "1.5", "tool_version": "1.5.0"},
}

QUERY = "What is the capital of France?"
CONTEXT = "France is a country in Western Europe. Its capital is Paris."
RESPONSE = "The capital of France is Paris."

_INPUTS = {"query": QUERY, "context": CONTEXT}
_OUTPUTS = {"response": RESPONSE}


def build_pass_receipt(cv: int) -> dict:
    versions = CV_VERSION_MAP[cv]
    receipt = {
        "spec_version": versions["spec_version"],
        "tool_version": versions["tool_version"],
        "checks_version": str(cv),
        "receipt_id": f"a000{cv:04d}-0000-4000-8000-{cv:012d}",
        "timestamp": "2026-01-01T00:00:00+00:00",
        "correlation_id": f"golden-v{cv}-pass-simple",
        "inputs": dict(_INPUTS),
        "outputs": dict(_OUTPUTS),
        # hash_obj(inputs) and hash_obj(outputs) match the verifier's
        # recomputation in verify_content_hashes (verify.py:653).
        "context_hash": hash_obj(_INPUTS),
        "output_hash": hash_obj(_OUTPUTS),
        "checks": [
            {
                "check_id": "C2",
                "name": "Mark Inferences",
                "passed": True,
                "severity": "info",
                "evidence": None,
                "details": "Response derivable from context without inference.",
            }
        ],
        "checks_failed": 0,
        "checks_passed": 1,
        "status": "PASS",
        "event_type": None,
        "content_mode": None,
        "content_mode_source": None,
        "context_limitation": None,
        # Nullable fields explicitly set to None for stability
        "constitution_ref": None,
        "enforcement": None,
        "parent_receipts": None,
        "workflow_id": None,
        "agent_model": None,
        "agent_model_provider": None,
        "agent_model_version": None,
    }
    # cv >= 8: enforcement_surface + invariants_scope required
    if cv >= 8:
        receipt["enforcement_surface"] = "middleware"
        receipt["invariants_scope"] = "full"
    # cv >= 9: tool_name required (skipped here -- cv=9 already covered)
    if cv >= 9:
        receipt["tool_name"] = "sanna"
    # cv = 10: agent_identity required (R6 binding per spec section 2.19)
    if cv >= 10:
        receipt["agent_identity"] = {
            "agent_session_id": f"session-v{cv}-golden-pass-simple",
        }
    # Compute and inject fingerprints via the centralized SAN-524 function.
    pair = compute_fingerprints(receipt)
    if pair is None:
        raise RuntimeError(
            f"compute_fingerprints returned None for cv={cv} -- missing "
            f"a required field for this cv level."
        )
    receipt["receipt_fingerprint"] = pair.receipt_fingerprint
    receipt["full_fingerprint"] = pair.full_fingerprint
    return receipt


def make_tampered(receipt: dict) -> dict:
    """Return a tampered copy: outputs.response mutated post-fingerprint.

    The verifier detects this by recomputing hash_obj(outputs) and
    comparing to the stored output_hash field (which still holds the
    original hash). receipt_id uses the a999- prefix matching the
    existing 999_tampered.json convention.
    """
    tampered = json.loads(json.dumps(receipt))  # deep copy
    cv = int(receipt["checks_version"])
    tampered["receipt_id"] = f"a999{cv:04d}-0000-4000-8000-{cv:012d}"
    tampered["outputs"]["response"] = "TAMPERED: response altered after fingerprint computation"
    # NOTE: do NOT update output_hash or fingerprints. The mismatch is the tamper signal.
    return tampered


def write(filename: str, receipt: dict) -> None:
    path = OUT / filename
    with open(path, "w") as f:
        json.dump(receipt, f, indent=2)
        f.write("\n")
    print(f"  {filename}: cv={receipt['checks_version']}, status={receipt['status']}")


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    print(f"Generating legacy-cv golden receipts -> {OUT}/")
    for cv in sorted(CV_VERSION_MAP.keys()):
        pass_receipt = build_pass_receipt(cv)
        write(f"v{cv}_pass_simple.json", pass_receipt)
        tampered = make_tampered(pass_receipt)
        write(f"v{cv}_tampered.json", tampered)
    print("Done. 10 fixtures written.")


if __name__ == "__main__":
    main()
