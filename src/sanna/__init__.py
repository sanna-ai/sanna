"""Sanna — Trust infrastructure for AI agents.

Checks reasoning during execution, halts when constraints are violated,
generates portable cryptographic receipts proving governance was enforced.
"""

from .version import __version__
from .middleware import sanna_observe, SannaResult, SannaHaltError
from .receipt import generate_receipt, SannaReceipt
from .verify import verify_receipt, VerificationResult
from .store import ReceiptStore
from .drift import DriftAnalyzer

__all__ = [
    "__version__",
    "sanna_observe",
    "SannaHaltError",
    "SannaResult",
    "generate_receipt",
    "SannaReceipt",
    "verify_receipt",
    "VerificationResult",
    "ReceiptStore",
    "DriftAnalyzer",
]


def __getattr__(name: str):
    """Provide helpful errors for names that moved to submodules."""
    _moved = {
        # constitution.py
        "Constitution": "sanna.constitution",
        "load_constitution": "sanna.constitution",
        "parse_constitution": "sanna.constitution",
        "sign_constitution": "sanna.constitution",
        "approve_constitution": "sanna.constitution",
        "save_constitution": "sanna.constitution",
        "scaffold_constitution": "sanna.constitution",
        "SannaConstitutionError": "sanna.constitution",
        "compute_constitution_hash": "sanna.constitution",
        "compute_content_hash": "sanna.constitution",
        "validate_constitution_data": "sanna.constitution",
        "validate_against_schema": "sanna.constitution",
        "constitution_to_receipt_ref": "sanna.constitution",
        "constitution_to_signable_dict": "sanna.constitution",
        "constitution_to_dict": "sanna.constitution",
        "verify_identity_claims": "sanna.constitution",
        "AgentIdentity": "sanna.constitution",
        "Boundary": "sanna.constitution",
        "Invariant": "sanna.constitution",
        "Provenance": "sanna.constitution",
        "ConstitutionSignature": "sanna.constitution",
        "HaltCondition": "sanna.constitution",
        "TrustTiers": "sanna.constitution",
        "TrustedSources": "sanna.constitution",
        "AuthorityBoundaries": "sanna.constitution",
        "EscalationRule": "sanna.constitution",
        "EscalationTargetConfig": "sanna.constitution",
        "ApprovalRecord": "sanna.constitution",
        "ApprovalChain": "sanna.constitution",
        "IdentityClaim": "sanna.constitution",
        "IdentityVerificationResult": "sanna.constitution",
        "IdentityVerificationSummary": "sanna.constitution",
        "ReasoningConfig": "sanna.constitution",
        "GLCCheckConfig": "sanna.constitution",
        "GLCMinimumSubstanceConfig": "sanna.constitution",
        "GLCNoParrotingConfig": "sanna.constitution",
        "GLCLLMCoherenceConfig": "sanna.constitution",
        # crypto.py
        "generate_keypair": "sanna.crypto",
        "load_key_metadata": "sanna.crypto",
        "sign_constitution_full": "sanna.crypto",
        "verify_constitution_full": "sanna.crypto",
        "sign_receipt": "sanna.crypto",
        "verify_receipt_signature": "sanna.crypto",
        "sanitize_for_signing": "sanna.crypto",
        # enforcement/
        "CheckConfig": "sanna.enforcement",
        "CustomInvariantRecord": "sanna.enforcement",
        "configure_checks": "sanna.enforcement",
        "INVARIANT_CHECK_MAP": "sanna.enforcement",
        "CHECK_REGISTRY": "sanna.enforcement",
        "AuthorityDecision": "sanna.enforcement",
        "evaluate_authority": "sanna.enforcement",
        "EscalationTarget": "sanna.enforcement",
        "EscalationResult": "sanna.enforcement",
        "execute_escalation": "sanna.enforcement",
        "register_escalation_callback": "sanna.enforcement",
        "clear_escalation_callbacks": "sanna.enforcement",
        "get_escalation_callback": "sanna.enforcement",
        # bundle.py
        "create_bundle": "sanna.bundle",
        "verify_bundle": "sanna.bundle",
        "BundleVerificationResult": "sanna.bundle",
        "BundleCheck": "sanna.bundle",
        # evaluators/
        "register_invariant_evaluator": "sanna.evaluators",
        "get_evaluator": "sanna.evaluators",
        "list_evaluators": "sanna.evaluators",
        "clear_evaluators": "sanna.evaluators",
        # hashing.py
        "hash_text": "sanna.hashing",
        "hash_obj": "sanna.hashing",
        "canonicalize_text": "sanna.hashing",
        # receipt.py
        "CheckResult": "sanna.receipt",
        "FinalAnswerProvenance": "sanna.receipt",
        "ConstitutionProvenance": "sanna.receipt",
        "HaltEvent": "sanna.receipt",
        "TOOL_VERSION": "sanna.receipt",
        "SPEC_VERSION": "sanna.receipt",
        "CHECKS_VERSION": "sanna.receipt",
        "Enforcement": "sanna.receipt",
        "extract_trace_data": "sanna.receipt",
        # verify.py
        "load_schema": "sanna.verify",
        "verify_constitution_chain": "sanna.verify",
        # drift.py
        "DriftReport": "sanna.drift",
        "AgentDriftSummary": "sanna.drift",
        "CheckDriftDetail": "sanna.drift",
        "export_drift_report": "sanna.drift",
        "export_drift_report_to_file": "sanna.drift",
        # constitution_diff.py
        "diff_constitutions": "sanna.constitution_diff",
        "DiffResult": "sanna.constitution_diff",
        "DiffEntry": "sanna.constitution_diff",
        # middleware.py (promoted helpers)
        "build_trace_data": "sanna.middleware",
        "generate_constitution_receipt": "sanna.middleware",
        # Removed
        "C3MReceipt": "removed — use SannaReceipt",
    }
    if name in _moved:
        raise AttributeError(
            f"'{name}' is no longer a top-level export. "
            f"Import from '{_moved[name]}' instead."
        )
    raise AttributeError(f"module 'sanna' has no attribute '{name}'")
