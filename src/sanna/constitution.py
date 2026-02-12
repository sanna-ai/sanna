"""
Sanna Constitution — policy authoring, signing, and binding.

Defines the constitution document format (YAML/JSON) and all operations:
load, parse, validate, sign (hash), convert to receipt reference, scaffold.

The constitution captures governance provenance: who defined the agent's
boundaries, what those boundaries are, and who approved them.
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
class Provenance:
    authored_by: str
    approved_by: list[str]
    approval_date: str
    approval_method: str
    change_history: list[dict[str, str]] = field(default_factory=list)


@dataclass
class AgentIdentity:
    agent_name: str
    domain: str
    description: str = ""


@dataclass
class Constitution:
    schema_version: str
    identity: AgentIdentity
    provenance: Provenance
    boundaries: list[Boundary]
    trust_tiers: TrustTiers = field(default_factory=TrustTiers)
    halt_conditions: list[HaltCondition] = field(default_factory=list)
    document_hash: Optional[str] = None
    signed_at: Optional[str] = None


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
    identity = AgentIdentity(
        agent_name=identity_data["agent_name"],
        domain=identity_data["domain"],
        description=identity_data.get("description", ""),
    )

    prov_data = data["provenance"]
    approved_by = prov_data["approved_by"]
    if isinstance(approved_by, str):
        approved_by = [approved_by]
    provenance = Provenance(
        authored_by=prov_data["authored_by"],
        approved_by=approved_by,
        approval_date=str(prov_data["approval_date"]),
        approval_method=prov_data["approval_method"],
        change_history=prov_data.get("change_history", []),
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

    return Constitution(
        schema_version=str(schema_version),
        identity=identity,
        provenance=provenance,
        boundaries=boundaries,
        trust_tiers=trust_tiers,
        halt_conditions=halt_conditions,
        document_hash=data.get("document_hash"),
        signed_at=data.get("signed_at"),
    )


# =============================================================================
# HASHING & SIGNING
# =============================================================================

def compute_constitution_hash(constitution: Constitution) -> str:
    """SHA-256 of canonical content. Returns FULL 64-character hex digest.

    Hash covers identity, boundaries, trust_tiers, halt_conditions
    but NOT provenance. Same policy = same hash regardless of who approved.
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

    hashable = {
        "identity": asdict(constitution.identity),
        "boundaries": boundaries,
        "trust_tiers": trust_tiers,
        "halt_conditions": halt_conditions,
    }

    canonical = json.dumps(hashable, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def sign_constitution(constitution: Constitution) -> Constitution:
    """Return new Constitution with document_hash and signed_at set."""
    doc_hash = compute_constitution_hash(constitution)
    return Constitution(
        schema_version=constitution.schema_version,
        identity=constitution.identity,
        provenance=constitution.provenance,
        boundaries=constitution.boundaries,
        trust_tiers=constitution.trust_tiers,
        halt_conditions=constitution.halt_conditions,
        document_hash=doc_hash,
        signed_at=datetime.now(timezone.utc).isoformat(),
    )


# =============================================================================
# RECEIPT BINDING
# =============================================================================

def constitution_to_receipt_ref(constitution: Constitution) -> dict:
    """Convert signed constitution to receipt's constitution_ref format.

    Raises ValueError if not signed.
    Returns: {document_id, document_hash, version, approved_by, approval_date, approval_method}
    """
    if not constitution.document_hash:
        raise ValueError("Constitution must be signed before binding to a receipt. Call sign_constitution() first.")

    return {
        "document_id": f"{constitution.identity.agent_name}/{constitution.schema_version}",
        "document_hash": constitution.document_hash,
        "version": constitution.schema_version,
        "approved_by": constitution.provenance.approved_by,
        "approval_date": constitution.provenance.approval_date,
        "approval_method": constitution.provenance.approval_method,
    }


# =============================================================================
# FILE I/O
# =============================================================================

def load_constitution(path: str | Path) -> Constitution:
    """Load from .yaml/.yml/.json file. Validates on load."""
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

    return parse_constitution(data)


def constitution_to_dict(constitution: Constitution) -> dict:
    """Serialize for YAML/JSON output.

    Reverses the mapping: Constitution.schema_version -> 'sanna_constitution' key.
    """
    result = {"sanna_constitution": constitution.schema_version}
    result["identity"] = asdict(constitution.identity)
    result["provenance"] = asdict(constitution.provenance)
    result["boundaries"] = [asdict(b) for b in constitution.boundaries]
    result["trust_tiers"] = asdict(constitution.trust_tiers)
    result["halt_conditions"] = [asdict(h) for h in constitution.halt_conditions]
    result["document_hash"] = constitution.document_hash
    result["signed_at"] = constitution.signed_at
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
#   3. Sign it:  sanna-sign-constitution constitution.yaml
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

# These fields are set by `sanna-sign-constitution` — do not edit manually:
document_hash: null
signed_at: null
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
