"""
Sanna Constitution — policy authoring, signing, and binding.

Defines the constitution document format (YAML/JSON) and all operations:
load, parse, validate, sign (hash), convert to receipt reference, scaffold.

The constitution captures governance provenance: who defined the agent's
boundaries, what those boundaries are, and who approved them.

v0.6.3: Constitution signature covers the full document (not just the hash).
Signature metadata lives in provenance.signature.  ``document_hash`` is
renamed to ``policy_hash`` everywhere.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


# =============================================================================
# EXCEPTIONS
# =============================================================================

class SannaConstitutionError(Exception):
    """Raised when a constitution fails integrity checks."""
    pass


# =============================================================================
# CONSTANTS
# =============================================================================

CONSTITUTION_SCHEMA_VERSION = "0.1.0"

VALID_CATEGORIES = {"scope", "authorization", "confidentiality", "safety", "compliance", "custom"}
VALID_SEVERITIES = {"critical", "high", "medium", "low", "info"}
VALID_ENFORCEMENT = {"halt", "warn", "log"}

_BOUNDARY_ID_RE = re.compile(r"^B\d{3}$")
_HALT_ID_RE = re.compile(r"^H\d{3}$")
_ISO8601_RE = re.compile(r"^\d{4}-\d{2}-\d{2}")


# =============================================================================
# DATA CLASSES
# =============================================================================

@dataclass
class Boundary:
    id: str
    description: str
    category: str
    severity: str


@dataclass
class HaltCondition:
    id: str
    trigger: str
    escalate_to: str
    severity: str
    enforcement: str


@dataclass
class TrustTiers:
    autonomous: list[str] = field(default_factory=list)
    requires_approval: list[str] = field(default_factory=list)
    prohibited: list[str] = field(default_factory=list)


@dataclass
class TrustedSources:
    """Source trust tiers for C1 source-aware context evaluation.

    Maps source names (e.g., MCP server names, database identifiers) to
    trust tiers that control how C1 weighs their content:

    - **tier_1**: Full trust — claims count as grounded evidence.
    - **tier_2**: Evidence with verification flag in receipt.
    - **tier_3**: Reference only — cannot be sole basis for conclusions.
    - **untrusted**: Excluded from C1 contradiction checking.
    """
    tier_1: list[str] = field(default_factory=list)
    tier_2: list[str] = field(default_factory=list)
    tier_3: list[str] = field(default_factory=list)
    untrusted: list[str] = field(default_factory=list)


@dataclass
class ConstitutionSignature:
    """Ed25519 signature block for a constitution document.

    Lives at ``provenance.signature`` in the constitution.  The ``value``
    field is excluded from the signed material (set to ``""`` during
    signing / verification).
    """
    value: Optional[str] = None        # Base64 Ed25519 signature
    key_id: Optional[str] = None       # SHA-256 fingerprint of signing public key (64 hex)
    signed_by: Optional[str] = None    # Identity of the signer
    signed_at: Optional[str] = None    # ISO 8601 timestamp
    scheme: str = "constitution_sig_v1"


@dataclass
class Provenance:
    authored_by: str
    approved_by: list[str]
    approval_date: str
    approval_method: str
    change_history: list[dict[str, str]] = field(default_factory=list)
    signature: Optional[ConstitutionSignature] = None


@dataclass
class AgentIdentity:
    agent_name: str
    domain: str
    description: str = ""
    extensions: dict = field(default_factory=dict)


@dataclass
class Invariant:
    id: str           # INV_NO_FABRICATION, INV_CUSTOM_*, etc.
    rule: str         # Human-readable description
    enforcement: str  # "halt" | "warn" | "log"
    check: Optional[str] = None  # Optional check impl ID (e.g., "sanna.context_contradiction")


@dataclass
class EscalationTargetConfig:
    """Escalation target configuration from a constitution YAML.

    Defines where/how an escalation is routed when a must_escalate
    condition triggers.

    Attributes:
        type: Target type — ``"log"``, ``"webhook"``, or ``"callback"``.
        url: Webhook URL (only for ``type="webhook"``).
        handler: Registered callback name (only for ``type="callback"``).
    """
    type: str = "log"
    url: Optional[str] = None
    handler: Optional[str] = None


@dataclass
class EscalationRule:
    """A must_escalate rule from a constitution's authority_boundaries.

    Attributes:
        condition: Natural-language description of when to escalate
            (e.g., ``"decisions involving PII"``).
        target: Optional escalation target override. When absent, the
            constitution's default escalation type is used.
    """
    condition: str
    target: Optional[EscalationTargetConfig] = None


@dataclass
class AuthorityBoundaries:
    """Authority boundary definitions from a constitution.

    Defines three tiers of action control:

    - **cannot_execute**: Actions the agent must never perform.
    - **must_escalate**: Conditions under which human/system review is required.
    - **can_execute**: Actions explicitly permitted for the agent.

    Attributes:
        cannot_execute: List of forbidden action descriptions.
        must_escalate: List of escalation rules with conditions and targets.
        can_execute: List of explicitly allowed action descriptions.
        default_escalation: Fallback escalation target type when a
            must_escalate rule has no explicit target.
    """
    cannot_execute: list[str] = field(default_factory=list)
    must_escalate: list[EscalationRule] = field(default_factory=list)
    can_execute: list[str] = field(default_factory=list)
    default_escalation: str = "log"


@dataclass
class Constitution:
    schema_version: str
    identity: AgentIdentity
    provenance: Provenance
    boundaries: list[Boundary]
    trust_tiers: TrustTiers = field(default_factory=TrustTiers)
    halt_conditions: list[HaltCondition] = field(default_factory=list)
    invariants: list[Invariant] = field(default_factory=list)
    policy_hash: Optional[str] = None
    authority_boundaries: Optional[AuthorityBoundaries] = None
    trusted_sources: Optional[TrustedSources] = None


# =============================================================================
# VALIDATION
# =============================================================================

def validate_constitution_data(data: dict) -> list[str]:
    """Return list of error strings. Empty = valid."""
    errors: list[str] = []

    # Top-level required keys
    for key in ("identity", "provenance", "boundaries"):
        if key not in data:
            errors.append(f"Missing required field: {key}")
    if errors:
        return errors

    # Identity
    identity = data.get("identity", {})
    if not isinstance(identity, dict):
        errors.append("identity must be a dict")
    else:
        if not identity.get("agent_name"):
            errors.append("identity.agent_name is required")
        if not identity.get("domain"):
            errors.append("identity.domain is required")

    # Provenance
    prov = data.get("provenance", {})
    if not isinstance(prov, dict):
        errors.append("provenance must be a dict")
    else:
        if not prov.get("authored_by"):
            errors.append("provenance.authored_by is required")
        approved_by = prov.get("approved_by")
        if isinstance(approved_by, str):
            approved_by = [approved_by]
        if not approved_by or not isinstance(approved_by, list) or len(approved_by) == 0:
            errors.append("provenance.approved_by must have at least one entry")
        approval_date = prov.get("approval_date", "")
        if not approval_date:
            errors.append("provenance.approval_date is required")
        elif not _ISO8601_RE.match(str(approval_date)):
            errors.append(f"provenance.approval_date is not valid ISO 8601: {approval_date}")
        if not prov.get("approval_method"):
            errors.append("provenance.approval_method is required")

    # Boundaries
    boundaries = data.get("boundaries", [])
    if not isinstance(boundaries, list) or len(boundaries) == 0:
        errors.append("boundaries must contain at least one boundary")
    else:
        seen_bids: set[str] = set()
        for i, b in enumerate(boundaries):
            if not isinstance(b, dict):
                errors.append(f"boundaries[{i}] must be a dict")
                continue
            bid = b.get("id", "")
            if not _BOUNDARY_ID_RE.match(bid):
                errors.append(f"boundaries[{i}].id '{bid}' must match B### pattern")
            if bid in seen_bids:
                errors.append(f"Duplicate boundary ID: {bid}")
            seen_bids.add(bid)
            if not b.get("description"):
                errors.append(f"boundaries[{i}].description is required")
            cat = b.get("category", "")
            if cat not in VALID_CATEGORIES:
                errors.append(f"boundaries[{i}].category '{cat}' must be one of {sorted(VALID_CATEGORIES)}")
            sev = b.get("severity", "")
            if sev not in VALID_SEVERITIES:
                errors.append(f"boundaries[{i}].severity '{sev}' must be one of {sorted(VALID_SEVERITIES)}")

    # Halt conditions (optional)
    halt_conditions = data.get("halt_conditions", [])
    if isinstance(halt_conditions, list):
        seen_hids: set[str] = set()
        for i, h in enumerate(halt_conditions):
            if not isinstance(h, dict):
                errors.append(f"halt_conditions[{i}] must be a dict")
                continue
            hid = h.get("id", "")
            if not _HALT_ID_RE.match(hid):
                errors.append(f"halt_conditions[{i}].id '{hid}' must match H### pattern")
            if hid in seen_hids:
                errors.append(f"Duplicate halt condition ID: {hid}")
            seen_hids.add(hid)
            if not h.get("trigger"):
                errors.append(f"halt_conditions[{i}].trigger is required")
            if not h.get("escalate_to"):
                errors.append(f"halt_conditions[{i}].escalate_to is required")
            sev = h.get("severity", "")
            if sev not in VALID_SEVERITIES:
                errors.append(f"halt_conditions[{i}].severity '{sev}' must be one of {sorted(VALID_SEVERITIES)}")
            enf = h.get("enforcement", "")
            if enf not in VALID_ENFORCEMENT:
                errors.append(f"halt_conditions[{i}].enforcement '{enf}' must be one of {sorted(VALID_ENFORCEMENT)}")

    # Invariants (optional)
    invariants = data.get("invariants", [])
    if isinstance(invariants, list):
        seen_inv_ids: set[str] = set()
        for i, inv in enumerate(invariants):
            if not isinstance(inv, dict):
                errors.append(f"invariants[{i}] must be a dict")
                continue
            inv_id = inv.get("id", "")
            if not inv_id:
                errors.append(f"invariants[{i}].id is required")
            if inv_id in seen_inv_ids:
                errors.append(f"Duplicate invariant ID: {inv_id}")
            seen_inv_ids.add(inv_id)
            if not inv.get("rule"):
                errors.append(f"invariants[{i}].rule is required")
            enf = inv.get("enforcement", "")
            if enf not in VALID_ENFORCEMENT:
                errors.append(f"invariants[{i}].enforcement '{enf}' must be one of {sorted(VALID_ENFORCEMENT)}")

    # Authority boundaries (optional, v0.7.0+)
    ab = data.get("authority_boundaries")
    if ab is not None:
        if not isinstance(ab, dict):
            errors.append("authority_boundaries must be a dict")
        else:
            for key in ("cannot_execute", "can_execute"):
                val = ab.get(key, [])
                if not isinstance(val, list):
                    errors.append(f"authority_boundaries.{key} must be a list")
            must_esc = ab.get("must_escalate", [])
            if not isinstance(must_esc, list):
                errors.append("authority_boundaries.must_escalate must be a list")
            else:
                for i, rule in enumerate(must_esc):
                    if not isinstance(rule, dict):
                        errors.append(f"authority_boundaries.must_escalate[{i}] must be a dict")
                    elif not rule.get("condition"):
                        errors.append(f"authority_boundaries.must_escalate[{i}].condition is required")

    return errors


# =============================================================================
# PARSING
# =============================================================================

def parse_constitution(data: dict) -> Constitution:
    """Parse from dict. Validates all fields."""
    errors = validate_constitution_data(data)
    if errors:
        raise ValueError(f"Invalid constitution: {'; '.join(errors)}")

    # Map sanna_constitution → schema_version
    schema_version = data.get("sanna_constitution", data.get("schema_version", CONSTITUTION_SCHEMA_VERSION))

    identity_data = data["identity"]
    _identity_known_keys = {"agent_name", "domain", "description"}
    identity = AgentIdentity(
        agent_name=identity_data["agent_name"],
        domain=identity_data["domain"],
        description=identity_data.get("description", ""),
        extensions={k: v for k, v in identity_data.items()
                    if k not in _identity_known_keys},
    )

    prov_data = data["provenance"]
    approved_by = prov_data["approved_by"]
    if isinstance(approved_by, str):
        approved_by = [approved_by]

    # Parse nested signature block if present
    sig_data = prov_data.get("signature")
    prov_signature = None
    if isinstance(sig_data, dict):
        prov_signature = ConstitutionSignature(
            value=sig_data.get("value"),
            key_id=sig_data.get("key_id"),
            signed_by=sig_data.get("signed_by"),
            signed_at=sig_data.get("signed_at"),
            scheme=sig_data.get("scheme", "constitution_sig_v1"),
        )

    provenance = Provenance(
        authored_by=prov_data["authored_by"],
        approved_by=approved_by,
        approval_date=str(prov_data["approval_date"]),
        approval_method=prov_data["approval_method"],
        change_history=prov_data.get("change_history", []),
        signature=prov_signature,
    )

    boundaries = [
        Boundary(
            id=b["id"],
            description=b["description"],
            category=b["category"],
            severity=b["severity"],
        )
        for b in data["boundaries"]
    ]

    trust_data = data.get("trust_tiers", {})
    if isinstance(trust_data, dict):
        trust_tiers = TrustTiers(
            autonomous=trust_data.get("autonomous", []),
            requires_approval=trust_data.get("requires_approval", []),
            prohibited=trust_data.get("prohibited", []),
        )
    else:
        trust_tiers = TrustTiers()

    halt_conditions = [
        HaltCondition(
            id=h["id"],
            trigger=h["trigger"],
            escalate_to=h["escalate_to"],
            severity=h["severity"],
            enforcement=h["enforcement"],
        )
        for h in data.get("halt_conditions", [])
    ]

    invariants = [
        Invariant(
            id=inv["id"],
            rule=inv["rule"],
            enforcement=inv["enforcement"],
            check=inv.get("check"),
        )
        for inv in data.get("invariants", [])
    ]

    # Authority boundaries (optional, v0.7.0+)
    authority_boundaries = None
    ab_data = data.get("authority_boundaries")
    if ab_data is not None and isinstance(ab_data, dict):
        et_data = data.get("escalation_targets", {})
        default_esc = et_data.get("default", "log") if isinstance(et_data, dict) else "log"

        cannot_execute = ab_data.get("cannot_execute", [])
        can_execute = ab_data.get("can_execute", [])

        must_escalate = []
        for rule_data in ab_data.get("must_escalate", []):
            if not isinstance(rule_data, dict):
                continue
            target_data = rule_data.get("target")
            target = None
            if isinstance(target_data, dict):
                target = EscalationTargetConfig(
                    type=target_data.get("type", "log"),
                    url=target_data.get("url"),
                    handler=target_data.get("handler"),
                )
            must_escalate.append(EscalationRule(
                condition=rule_data.get("condition", ""),
                target=target,
            ))

        authority_boundaries = AuthorityBoundaries(
            cannot_execute=cannot_execute,
            must_escalate=must_escalate,
            can_execute=can_execute,
            default_escalation=default_esc,
        )

    # Trusted sources (optional, v0.7.0+)
    trusted_sources = None
    ts_data = data.get("trusted_sources")
    if ts_data is not None and isinstance(ts_data, dict):
        trusted_sources = TrustedSources(
            tier_1=ts_data.get("tier_1", []),
            tier_2=ts_data.get("tier_2", []),
            tier_3=ts_data.get("tier_3", []),
            untrusted=ts_data.get("untrusted", []),
        )

    return Constitution(
        schema_version=str(schema_version),
        identity=identity,
        provenance=provenance,
        boundaries=boundaries,
        trust_tiers=trust_tiers,
        halt_conditions=halt_conditions,
        invariants=invariants,
        policy_hash=data.get("policy_hash"),
        authority_boundaries=authority_boundaries,
        trusted_sources=trusted_sources,
    )


# =============================================================================
# HASHING & SIGNING
# =============================================================================

def _identity_dict(identity: AgentIdentity) -> dict:
    """Convert AgentIdentity to dict, flattening extensions into top level.

    Extensions are stored as a nested dict in the dataclass but represented
    as flat keys in YAML/JSON.  This function flattens them back so that:

    - Empty extensions → same dict as before (backward compat).
    - Non-empty extensions → flat keys alongside agent_name/domain/description,
      matching the original YAML representation.
    """
    d = {
        "agent_name": identity.agent_name,
        "domain": identity.domain,
        "description": identity.description,
    }
    if identity.extensions:
        d.update(identity.extensions)
    return d


def compute_constitution_hash(constitution: Constitution) -> str:
    """SHA-256 of canonical content. Returns FULL 64-character hex digest.

    Hash covers identity, boundaries, trust_tiers, halt_conditions
    but NOT provenance. Same policy = same hash regardless of who approved.

    .. note::

       policy_hash uses ``json.dumps(sort_keys=True, ensure_ascii=True)``.
       This differs from RFC 8785 (JCS) which uses ``ensure_ascii=False``.
       The choice is intentional for v0.7.x: ``ensure_ascii=True`` produces
       ASCII-safe hashes that are portable across JSON parsers that may
       handle Unicode normalization differently.  Cross-language implementors
       should use ``ensure_ascii=True`` (Python default) or equivalent ASCII
       escaping for Unicode characters.
    """
    # Sort boundaries by ID for determinism
    boundaries = sorted(
        [asdict(b) for b in constitution.boundaries],
        key=lambda b: b["id"],
    )
    # Sort halt conditions by ID
    halt_conditions = sorted(
        [asdict(h) for h in constitution.halt_conditions],
        key=lambda h: h["id"],
    )
    # Sort trust tier lists alphabetically
    trust_tiers = {
        "autonomous": sorted(constitution.trust_tiers.autonomous),
        "requires_approval": sorted(constitution.trust_tiers.requires_approval),
        "prohibited": sorted(constitution.trust_tiers.prohibited),
    }

    invariants = sorted(
        [asdict(inv) for inv in constitution.invariants],
        key=lambda inv: inv["id"],
    )

    hashable = {
        "identity": _identity_dict(constitution.identity),
        "boundaries": boundaries,
        "trust_tiers": trust_tiers,
        "halt_conditions": halt_conditions,
        "invariants": invariants,
    }

    # Include authority_boundaries only if present (backward compat:
    # constitutions without this field produce the same hash as before)
    if constitution.authority_boundaries is not None:
        hashable["authority_boundaries"] = asdict(constitution.authority_boundaries)

    # Include trusted_sources only if present (backward compat)
    if constitution.trusted_sources is not None:
        hashable["trusted_sources"] = asdict(constitution.trusted_sources)

    canonical = json.dumps(hashable, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def constitution_to_signable_dict(constitution: Constitution) -> dict:
    """Build the canonical dict that gets Ed25519-signed.

    Includes the full document (identity, provenance with signature block,
    boundaries, trust_tiers, halt_conditions, invariants, policy_hash).
    The only exclusion is ``provenance.signature.value`` which is set to
    ``""`` in the signable representation.
    """
    prov_dict = {
        "authored_by": constitution.provenance.authored_by,
        "approved_by": constitution.provenance.approved_by,
        "approval_date": constitution.provenance.approval_date,
        "approval_method": constitution.provenance.approval_method,
        "change_history": constitution.provenance.change_history,
    }

    # Include signature block with value blanked out
    sig = constitution.provenance.signature
    if sig is not None:
        prov_dict["signature"] = {
            "value": "",  # excluded from signing
            "key_id": sig.key_id,
            "signed_by": sig.signed_by,
            "signed_at": sig.signed_at,
            "scheme": sig.scheme,
        }
    else:
        prov_dict["signature"] = None

    result = {
        "schema_version": constitution.schema_version,
        "identity": _identity_dict(constitution.identity),
        "provenance": prov_dict,
        "boundaries": [asdict(b) for b in constitution.boundaries],
        "trust_tiers": asdict(constitution.trust_tiers),
        "halt_conditions": [asdict(h) for h in constitution.halt_conditions],
        "invariants": [asdict(inv) for inv in constitution.invariants],
        "policy_hash": constitution.policy_hash,
    }

    if constitution.authority_boundaries is not None:
        result["authority_boundaries"] = asdict(constitution.authority_boundaries)
        result["escalation_targets"] = {
            "default": constitution.authority_boundaries.default_escalation,
        }

    if constitution.trusted_sources is not None:
        result["trusted_sources"] = asdict(constitution.trusted_sources)

    return result


def sign_constitution(
    constitution: Constitution,
    private_key_path: Optional[str] = None,
    signed_by: Optional[str] = None,
) -> Constitution:
    """Return new Constitution with policy_hash (and optional Ed25519 signature).

    Args:
        constitution: The constitution to sign.
        private_key_path: Optional path to Ed25519 private key for cryptographic signing.
        signed_by: Optional identity of the signer.
    """
    policy_hash = compute_constitution_hash(constitution)

    prov_signature = None

    if private_key_path is not None:
        from .crypto import sign_constitution_full
        # Build a constitution with policy_hash set but no signature yet,
        # so sign_constitution_full can build the signable dict.
        pre_signed = Constitution(
            schema_version=constitution.schema_version,
            identity=constitution.identity,
            provenance=Provenance(
                authored_by=constitution.provenance.authored_by,
                approved_by=constitution.provenance.approved_by,
                approval_date=constitution.provenance.approval_date,
                approval_method=constitution.provenance.approval_method,
                change_history=constitution.provenance.change_history,
                signature=None,  # will be filled in by sign_constitution_full
            ),
            boundaries=constitution.boundaries,
            trust_tiers=constitution.trust_tiers,
            halt_conditions=constitution.halt_conditions,
            invariants=constitution.invariants,
            policy_hash=policy_hash,
            authority_boundaries=constitution.authority_boundaries,
            trusted_sources=constitution.trusted_sources,
        )
        prov_signature = sign_constitution_full(pre_signed, private_key_path, signed_by=signed_by)

    return Constitution(
        schema_version=constitution.schema_version,
        identity=constitution.identity,
        provenance=Provenance(
            authored_by=constitution.provenance.authored_by,
            approved_by=constitution.provenance.approved_by,
            approval_date=constitution.provenance.approval_date,
            approval_method=constitution.provenance.approval_method,
            change_history=constitution.provenance.change_history,
            signature=prov_signature,
        ),
        boundaries=constitution.boundaries,
        trust_tiers=constitution.trust_tiers,
        halt_conditions=constitution.halt_conditions,
        invariants=constitution.invariants,
        policy_hash=policy_hash,
        authority_boundaries=constitution.authority_boundaries,
        trusted_sources=constitution.trusted_sources,
    )


# =============================================================================
# RECEIPT BINDING
# =============================================================================

def constitution_to_receipt_ref(constitution: Constitution) -> dict:
    """Convert signed constitution to receipt's constitution_ref format.

    Raises ValueError if not signed (no policy_hash).
    """
    if not constitution.policy_hash:
        raise ValueError("Constitution must be signed before binding to a receipt. Call sign_constitution() first.")

    ref = {
        "document_id": f"{constitution.identity.agent_name}/{constitution.schema_version}",
        "policy_hash": constitution.policy_hash,
        "version": constitution.schema_version,
        "approved_by": constitution.provenance.approved_by,
        "approval_date": constitution.provenance.approval_date,
        "approval_method": constitution.provenance.approval_method,
    }
    sig = constitution.provenance.signature
    if sig is not None and sig.value is not None:
        ref["signature"] = sig.value
        ref["key_id"] = sig.key_id
        ref["signed_by"] = sig.signed_by
        ref["signed_at"] = sig.signed_at
        ref["scheme"] = sig.scheme
    return ref


# =============================================================================
# FILE I/O
# =============================================================================

def load_constitution(path: str | Path, validate: bool = False) -> Constitution:
    """Load from .yaml/.yml/.json file. Validates on load.

    Args:
        path: Path to constitution file.
        validate: If True, validate against the JSON schema before parsing.
            Raises SannaConstitutionError on schema violation.
    """
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Constitution file not found: {path}")

    with open(path) as f:
        if path.suffix in (".yaml", ".yml"):
            import yaml
            data = yaml.safe_load(f)
        elif path.suffix == ".json":
            data = json.load(f)
        else:
            raise ValueError(f"Unsupported file format: {path.suffix} (use .yaml, .yml, or .json)")

    if not isinstance(data, dict):
        raise ValueError(f"Constitution file must contain a YAML/JSON object, got {type(data).__name__}")

    if validate:
        schema_errors = validate_against_schema(data)
        if schema_errors:
            raise SannaConstitutionError(
                f"Constitution schema validation failed: {'; '.join(schema_errors)}"
            )

    constitution = parse_constitution(data)

    # Verify hash integrity if constitution is signed
    if constitution.policy_hash:
        computed = compute_constitution_hash(constitution)
        if computed != constitution.policy_hash:
            raise SannaConstitutionError(
                f"Constitution hash mismatch: file has been modified since signing. "
                f"Expected {constitution.policy_hash[:16]}..., got {computed[:16]}... "
                f"Re-sign with: sanna-sign-constitution {path}"
            )

    return constitution


def validate_against_schema(data: dict) -> list[str]:
    """Validate a constitution data dict against the JSON schema.

    Returns list of error strings. Empty list = valid.
    """
    from jsonschema import validate as jschema_validate, ValidationError

    schema_path = Path(__file__).parent / "spec" / "constitution.schema.json"
    with open(schema_path) as f:
        schema = json.load(f)

    errors = []
    try:
        jschema_validate(data, schema)
    except ValidationError as e:
        msg = f"Schema validation failed: {e.message}"
        if e.path:
            msg += f" (at {'.'.join(str(p) for p in e.path)})"
        errors.append(msg)
    return errors


def constitution_to_dict(constitution: Constitution) -> dict:
    """Serialize for YAML/JSON output.

    Reverses the mapping: Constitution.schema_version -> 'sanna_constitution' key.
    """
    result = {"sanna_constitution": constitution.schema_version}
    result["identity"] = _identity_dict(constitution.identity)

    # Build provenance dict with nested signature block
    prov_dict = {
        "authored_by": constitution.provenance.authored_by,
        "approved_by": constitution.provenance.approved_by,
        "approval_date": constitution.provenance.approval_date,
        "approval_method": constitution.provenance.approval_method,
        "change_history": constitution.provenance.change_history,
    }
    sig = constitution.provenance.signature
    if sig is not None:
        prov_dict["signature"] = {
            "value": sig.value,
            "key_id": sig.key_id,
            "signed_by": sig.signed_by,
            "signed_at": sig.signed_at,
            "scheme": sig.scheme,
        }
    result["provenance"] = prov_dict

    result["boundaries"] = [asdict(b) for b in constitution.boundaries]
    result["trust_tiers"] = asdict(constitution.trust_tiers)
    result["halt_conditions"] = [asdict(h) for h in constitution.halt_conditions]
    if constitution.invariants:
        result["invariants"] = [asdict(inv) for inv in constitution.invariants]

    if constitution.authority_boundaries is not None:
        ab = constitution.authority_boundaries
        must_escalate_list = []
        for rule in ab.must_escalate:
            rd: dict = {"condition": rule.condition}
            if rule.target is not None:
                rd["target"] = asdict(rule.target)
            must_escalate_list.append(rd)
        result["authority_boundaries"] = {
            "cannot_execute": ab.cannot_execute,
            "must_escalate": must_escalate_list,
            "can_execute": ab.can_execute,
        }
        result["escalation_targets"] = {"default": ab.default_escalation}

    if constitution.trusted_sources is not None:
        result["trusted_sources"] = asdict(constitution.trusted_sources)

    result["policy_hash"] = constitution.policy_hash
    return result


def save_constitution(constitution: Constitution, path: str | Path) -> Path:
    """Save to .yaml/.yml/.json file."""
    path = Path(path)
    data = constitution_to_dict(constitution)

    with open(path, "w") as f:
        if path.suffix in (".yaml", ".yml"):
            import yaml
            yaml.dump(data, f, default_flow_style=False, sort_keys=False, allow_unicode=True)
        elif path.suffix == ".json":
            json.dump(data, f, indent=2)
        else:
            raise ValueError(f"Unsupported file format: {path.suffix}")

    return path


# =============================================================================
# SCAFFOLDING
# =============================================================================

_SCAFFOLD_TEMPLATE = """\
# Sanna Constitution — Agent Governance Document
#
# This file defines the boundaries, trust tiers, and halt conditions
# for your AI agent. It answers: "Who defined these boundaries, and what are they?"
#
# Workflow:
#   1. Edit this file with your agent's specific constraints
#   2. Get approval from your compliance/risk team
#   3. Sign it:  sanna-sign-constitution constitution.yaml --private-key sanna_ed25519.key
#   4. Wire it into your agent:
#        @sanna_observe(constitution_path="constitution.yaml")

sanna_constitution: "0.1.0"

identity:
  agent_name: "my-agent"            # Unique name for your agent
  domain: "my-domain"               # Business domain (e.g., "customer-service", "finance")
  description: ""                   # Optional description of what this agent does

provenance:
  authored_by: "you@company.com"    # Who wrote this constitution
  approved_by:                      # Who approved it (at least one)
    - "approver@company.com"
  approval_date: "{today}"          # When it was approved (ISO 8601)
  approval_method: "manual-sign-off"  # How it was approved
  change_history: []                # Version history (populated over time)

boundaries:
  # Each boundary defines a constraint the agent must operate within.
  # Categories: scope, authorization, confidentiality, safety, compliance, custom
  # Severities: critical, high, medium, low, info
  - id: "B001"
    description: "Only answer questions within the defined domain"
    category: "scope"
    severity: "high"

trust_tiers:
  autonomous:                       # Actions the agent can take without approval
    - "Answer domain questions"
  requires_approval:                # Actions needing human approval
    - "Escalate to specialist"
  prohibited:                       # Actions the agent must never take
    - "Make binding commitments"

halt_conditions:
  # Each halt condition defines when the agent should stop.
  # Enforcement: halt (stop execution), warn (continue with warning), log (record only)
  - id: "H001"
    trigger: "Agent contradicts verified information"
    escalate_to: "team-lead@company.com"
    severity: "critical"
    enforcement: "halt"

invariants:
  # Each invariant maps to a coherence check.
  # Standard IDs: INV_NO_FABRICATION, INV_MARK_INFERENCE, INV_NO_FALSE_CERTAINTY,
  #               INV_PRESERVE_TENSION, INV_NO_PREMATURE_COMPRESSION
  # Custom IDs:   INV_CUSTOM_* (appear in receipt as NOT_CHECKED)
  # Enforcement:  halt (stop execution), warn (continue with warning), log (record only)
  - id: "INV_NO_FABRICATION"
    rule: "Do not claim facts absent from provided sources."
    enforcement: "halt"
  - id: "INV_MARK_INFERENCE"
    rule: "Clearly mark inferences and speculation as such."
    enforcement: "warn"

# This field is set by `sanna-sign-constitution` — do not edit manually:
policy_hash: null
"""


def scaffold_constitution(output_path: str | Path | None = None) -> str:
    """Generate a scaffold constitution YAML with inline documentation.

    If output_path provided, write to file. Returns content string.
    """
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    content = _SCAFFOLD_TEMPLATE.replace("{today}", today)

    if output_path is not None:
        path = Path(output_path)
        with open(path, "w") as f:
            f.write(content)

    return content
