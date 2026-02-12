"""
Sanna — Coherence checks for AI agents.

Generates portable, offline-verifiable "reasoning receipts" that document
AI agent decisions with C1-C5 coherence checks and consistency-verified hashing.
"""

__version__ = "0.5.0"

from .hashing import hash_text, hash_obj, canonicalize_text
from .receipt import (
    generate_receipt,
    extract_trace_data,
    SannaReceipt,
    C3MReceipt,  # legacy alias
    CheckResult,
    FinalAnswerProvenance,
    ConstitutionProvenance,
    HaltEvent,
    TOOL_VERSION,
    SCHEMA_VERSION,
    CHECKS_VERSION,
)
from .verify import verify_receipt, load_schema, VerificationResult
from .middleware import sanna_observe, SannaResult, SannaHaltError
from .constitution import (
    Constitution,
    Boundary,
    HaltCondition,
    TrustTiers,
    Provenance,
    AgentIdentity,
    load_constitution,
    parse_constitution,
    validate_constitution_data,
    compute_constitution_hash,
    sign_constitution,
    constitution_to_receipt_ref,
    constitution_to_dict,
    save_constitution,
    scaffold_constitution,
)

__all__ = [
    "__version__",
    "hash_text",
    "hash_obj",
    "canonicalize_text",
    "generate_receipt",
    "extract_trace_data",
    "SannaReceipt",
    "C3MReceipt",
    "CheckResult",
    "FinalAnswerProvenance",
    "ConstitutionProvenance",
    "HaltEvent",
    "verify_receipt",
    "load_schema",
    "VerificationResult",
    "TOOL_VERSION",
    "SCHEMA_VERSION",
    "CHECKS_VERSION",
    "sanna_observe",
    "SannaResult",
    "SannaHaltError",
    "Constitution",
    "Boundary",
    "HaltCondition",
    "TrustTiers",
    "Provenance",
    "AgentIdentity",
    "load_constitution",
    "parse_constitution",
    "validate_constitution_data",
    "compute_constitution_hash",
    "sign_constitution",
    "constitution_to_receipt_ref",
    "constitution_to_dict",
    "save_constitution",
    "scaffold_constitution",
]
