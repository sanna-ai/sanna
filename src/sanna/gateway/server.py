"""Gateway MCP server — transparent proxy to downstream MCP servers.

Re-exposes downstream tools with prefixed names ({server_name}_{tool_name}).
Full schema fidelity: inputSchema, description, annotations all preserved.
Only the tool name changes.

Uses the low-level ``mcp.server.lowlevel.Server`` so the ``call_tool``
handler can return ``CallToolResult`` directly (preserving ``isError``
from downstream).

Block C adds constitution enforcement: every tool call is evaluated
against authority boundaries before forwarding, and every action
generates a signed reasoning receipt.

Block E adds must_escalate UX: escalated tool calls are held pending
until explicitly approved or denied via gateway meta-tools
(``sanna_approve_escalation`` / ``sanna_deny_escalation``).

Supports multiple downstream servers. Each downstream gets its own
namespace prefix, policy overrides, and independent circuit breaker.
"""

from __future__ import annotations

import copy
import enum
import hashlib
import hmac
import json
import logging
import asyncio as _asyncio
import os
import stat
import sys
import time as _time_mod
import unicodedata
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import mcp.types as types
from mcp.server.lowlevel import Server
from mcp.server.stdio import stdio_server

from sanna.gateway.mcp_client import (
    DownstreamConnection,
    DownstreamConnectionError,
)

logger = logging.getLogger("sanna.gateway.server")

# Gateway meta-tool names — never prefixed with server name
_META_TOOL_APPROVE = "sanna_approve_escalation"
_META_TOOL_DENY = "sanna_deny_escalation"
_META_TOOL_NAMES = frozenset({_META_TOOL_APPROVE, _META_TOOL_DENY})

# Default escalation timeout (seconds)
_DEFAULT_ESCALATION_TIMEOUT = 300  # 5 minutes

# Circuit breaker threshold — consecutive connection failures before
# marking the downstream as unhealthy
_CIRCUIT_BREAKER_THRESHOLD = 3

# Default circuit breaker cooldown (seconds) — time in OPEN state
# before transitioning to HALF_OPEN for a probe call
_DEFAULT_CIRCUIT_BREAKER_COOLDOWN = 60.0

# Valid redaction modes
_VALID_REDACTION_MODES = frozenset({"hash_only", "pattern_redact"})


# ---------------------------------------------------------------------------
# PII redaction for receipt storage (Block G)
# ---------------------------------------------------------------------------

def _redact_for_storage(
    content: str,
    mode: str = "hash_only",
    salt: str = "",
    secret: bytes | None = None,
) -> str:
    """Replace content with a redacted placeholder for receipt storage.

    Args:
        content: The original content to redact.
        mode: Redaction mode — ``"hash_only"`` replaces with HMAC-SHA256.
        salt: Per-receipt salt (e.g. receipt_id) appended before hashing.
            Prevents rainbow-table reversal of low-entropy inputs.
        secret: Gateway HMAC secret. When provided, uses HMAC-SHA256
            instead of plain SHA-256 (prevents offline brute-force).

    Returns:
        Redacted string with HMAC hash reference for auditability.
    """
    if mode == "hash_only":
        # NFC-normalize Unicode before hashing so that equivalent
        # representations (e.g. e + combining-acute vs. precomposed e-acute)
        # always produce the same redaction hash.
        normalized = unicodedata.normalize("NFC", content)
        payload = (normalized + salt).encode()
        if secret:
            digest = hmac.new(secret, payload, hashlib.sha256).hexdigest()
            return f"[REDACTED \u2014 HMAC-SHA256: {digest}]"
        # Fallback for callers without a secret (shouldn't happen in practice)
        digest = hashlib.sha256(payload).hexdigest()
        return f"[REDACTED \u2014 SHA-256-SALTED: {digest}]"
    # "pattern_redact" should be rejected at config load time; raise here
    # as defense-in-depth if it somehow reaches the runtime path.
    raise ValueError(
        f"Unsupported redaction mode: '{mode}'. "
        f"pattern_redact is not yet implemented."
    )


def _make_redaction_marker(original_value: str) -> dict:
    """Build a deterministic redaction marker for a field value.

    The marker replaces the original value in the receipt BEFORE signing,
    so that ``context_hash``/``output_hash`` and the receipt signature
    all cover the marker (not the original content).

    The ``original_hash`` is the SHA-256 hex digest of the original
    string value, allowing offline auditors to confirm provenance
    without access to the raw PII.

    Args:
        original_value: The raw string to redact.

    Returns:
        Deterministic marker dict:
        ``{"__redacted__": True, "original_hash": "<sha256-hex>"}``
    """
    normalized = unicodedata.normalize("NFC", original_value)
    digest = hashlib.sha256(normalized.encode("utf-8")).hexdigest()
    return {"__redacted__": True, "original_hash": digest}


def _apply_redaction_markers(receipt: dict, redaction_fields: list[str]) -> tuple[dict, list[str]]:
    """Replace redactable field values with deterministic markers.

    Modifies the receipt **in place** and recomputes ``context_hash``,
    ``output_hash``, ``receipt_fingerprint``, and ``full_fingerprint``
    so that the receipt is internally consistent with the markers.

    Must be called BEFORE signing.

    Args:
        receipt: The receipt dict (mutated in place).
        redaction_fields: List of field names to redact
            (``"arguments"`` maps to ``inputs.context``,
             ``"result_text"`` maps to ``outputs.response``).

    Returns:
        A tuple of ``(receipt, redacted_paths)`` where
        ``redacted_paths`` is a list of JSON-path strings
        for fields that were actually redacted.
    """
    from sanna.hashing import hash_obj, hash_text, EMPTY_HASH

    redacted_paths: list[str] = []

    # Apply markers to specified fields
    if "arguments" in redaction_fields:
        ctx = (receipt.get("inputs") or {}).get("context")
        if ctx:
            # FIX-12: If the value is already a dict with __redacted__: True,
            # an attacker may have pre-populated a fake redaction marker.
            # Serialize the entire dict as JSON and re-redact it as content.
            if isinstance(ctx, dict) and ctx.get("__redacted__") is True:
                logger.warning(
                    "Pre-existing redaction marker detected in inputs.context — "
                    "re-redacting to prevent marker injection"
                )
                ctx = json.dumps(ctx, sort_keys=True)
                receipt["inputs"]["context"] = _make_redaction_marker(ctx)
                redacted_paths.append("inputs.context")
            elif isinstance(ctx, str):
                receipt["inputs"]["context"] = _make_redaction_marker(ctx)
                redacted_paths.append("inputs.context")

    if "result_text" in redaction_fields:
        resp = (receipt.get("outputs") or {}).get("response")
        if resp:
            # FIX-12: Same injection guard for outputs.response
            if isinstance(resp, dict) and resp.get("__redacted__") is True:
                logger.warning(
                    "Pre-existing redaction marker detected in outputs.response — "
                    "re-redacting to prevent marker injection"
                )
                resp = json.dumps(resp, sort_keys=True)
                receipt["outputs"]["response"] = _make_redaction_marker(resp)
                redacted_paths.append("outputs.response")
            elif isinstance(resp, str):
                receipt["outputs"]["response"] = _make_redaction_marker(resp)
                redacted_paths.append("outputs.response")

    if not redacted_paths:
        return receipt, redacted_paths

    # Recompute content hashes from marker-bearing inputs/outputs
    inputs = receipt.get("inputs", {})
    outputs = receipt.get("outputs", {})
    context_hash = hash_obj(inputs)
    output_hash = hash_obj(outputs)
    receipt["context_hash"] = context_hash
    receipt["output_hash"] = output_hash

    # Record redaction metadata
    receipt["redacted_fields"] = redacted_paths

    # Recompute fingerprint (v0.13.0 unified 12-field formula)
    correlation_id = receipt.get("correlation_id", "")
    checks_version = receipt.get("checks_version", "")

    checks = receipt.get("checks", [])
    checks_data = [
        {
            "check_id": c.get("check_id", ""),
            "passed": c.get("passed"),
            "severity": c.get("severity", ""),
            "evidence": c.get("evidence"),
            "triggered_by": c.get("triggered_by"),
            "enforcement_level": c.get("enforcement_level"),
            "check_impl": c.get("check_impl"),
            "replayable": c.get("replayable"),
        }
        for c in checks
    ]
    checks_hash = hash_obj(checks_data)

    constitution_ref = receipt.get("constitution_ref")
    if constitution_ref:
        _cref = {k: v for k, v in constitution_ref.items() if k != "constitution_approval"}
        constitution_hash = hash_obj(_cref)
    else:
        constitution_hash = EMPTY_HASH

    enforcement = receipt.get("enforcement")
    enforcement_hash = hash_obj(enforcement) if enforcement else EMPTY_HASH

    evaluation_coverage = receipt.get("evaluation_coverage")
    coverage_hash = hash_obj(evaluation_coverage) if evaluation_coverage else EMPTY_HASH

    authority_decisions = receipt.get("authority_decisions")
    authority_hash = hash_obj(authority_decisions) if authority_decisions else EMPTY_HASH

    escalation_events = receipt.get("escalation_events")
    escalation_hash = hash_obj(escalation_events) if escalation_events else EMPTY_HASH

    source_trust_evaluations = receipt.get("source_trust_evaluations")
    trust_hash = hash_obj(source_trust_evaluations) if source_trust_evaluations else EMPTY_HASH

    extensions = receipt.get("extensions")
    extensions_hash = hash_obj(extensions) if extensions else EMPTY_HASH

    fingerprint_input = (
        f"{correlation_id}|{context_hash}|{output_hash}|{checks_version}"
        f"|{checks_hash}|{constitution_hash}|{enforcement_hash}"
        f"|{coverage_hash}|{authority_hash}|{escalation_hash}"
        f"|{trust_hash}|{extensions_hash}"
    )

    receipt["full_fingerprint"] = hash_text(fingerprint_input)
    receipt["receipt_fingerprint"] = hash_text(fingerprint_input, truncate=16)

    return receipt, redacted_paths


# ---------------------------------------------------------------------------
# Utility: safe text extraction from MCP tool results
# ---------------------------------------------------------------------------

def _extract_result_text(tool_result: types.CallToolResult | None) -> str:
    """Safely extract text from an MCP tool result for hashing and receipts.

    Handles empty content, non-text content types (images, resources),
    and None results without crashing.
    """
    if tool_result is None or not tool_result.content:
        return ""
    parts: list[str] = []
    for item in tool_result.content:
        if hasattr(item, "text") and item.text is not None:
            parts.append(item.text)
        elif hasattr(item, "type"):
            parts.append(f"[{item.type} content]")
        else:
            parts.append("[unknown content]")
    return "\n".join(parts)


class DuplicateToolError(Exception):
    """Raised when two downstream servers register the same prefixed tool name."""


class CircuitState(enum.Enum):
    """Circuit breaker states for downstream health tracking."""
    CLOSED = "closed"      # healthy — all calls forwarded normally
    OPEN = "open"          # unhealthy — calls blocked immediately
    HALF_OPEN = "half_open"  # probing — one call forwarded as probe


# ---------------------------------------------------------------------------
# Multi-downstream data models
# ---------------------------------------------------------------------------

@dataclass
class DownstreamSpec:
    """Per-downstream configuration for the gateway constructor.

    Bundles connection parameters and per-server policy configuration.
    Used by the multi-downstream constructor path and by ``run_gateway()``.
    """
    name: str
    command: str
    args: list[str] = field(default_factory=list)
    env: dict[str, str] | None = None
    timeout: float = 30.0
    policy_overrides: dict[str, str] = field(default_factory=dict)
    default_policy: str | None = None
    circuit_breaker_cooldown: float = _DEFAULT_CIRCUIT_BREAKER_COOLDOWN
    optional: bool = False


@dataclass
class _DownstreamState:
    """Runtime state for a single downstream connection.

    Holds the connection, circuit breaker state, and per-downstream
    tool map. One instance per downstream server.
    """
    spec: DownstreamSpec
    connection: DownstreamConnection | None = None
    tool_map: dict[str, str] = field(default_factory=dict)
    circuit_state: CircuitState = CircuitState.CLOSED
    circuit_opened_at: datetime | None = None
    consecutive_failures: int = 0


# ---------------------------------------------------------------------------
# Pending escalation store
# ---------------------------------------------------------------------------

@dataclass
class PendingEscalation:
    """A tool call held pending user approval."""
    escalation_id: str
    prefixed_name: str
    original_name: str
    arguments: dict[str, Any]
    server_name: str
    reason: str
    created_at: str  # ISO 8601
    escalation_receipt_id: str = ""
    token_hash: str = ""  # SHA-256 of the HMAC approval token
    status: str = "pending"  # pending | approved | failed
    override_reason: str = ""
    override_detail: str = ""
    issued_at: int = 0  # epoch seconds (int, not float) for HMAC re-derivation
    args_digest: str = ""  # SHA-256 hex of canonical arguments for HMAC re-derivation

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-safe dict for disk persistence."""
        return {
            "escalation_id": self.escalation_id,
            "prefixed_name": self.prefixed_name,
            "original_name": self.original_name,
            "arguments": self.arguments,
            "server_name": self.server_name,
            "reason": self.reason,
            "created_at": self.created_at,
            "escalation_receipt_id": self.escalation_receipt_id,
            "token_hash": self.token_hash,
            "status": self.status,
            "override_reason": self.override_reason,
            "override_detail": self.override_detail,
            "issued_at": self.issued_at,
            "args_digest": self.args_digest,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> PendingEscalation:
        """Deserialize from a dict (loaded from disk)."""
        return cls(
            escalation_id=data["escalation_id"],
            prefixed_name=data["prefixed_name"],
            original_name=data["original_name"],
            arguments=data.get("arguments", {}),
            server_name=data["server_name"],
            reason=data.get("reason", ""),
            created_at=data["created_at"],
            escalation_receipt_id=data.get("escalation_receipt_id", ""),
            token_hash=data.get("token_hash", ""),
            status=data.get("status", "pending"),
            override_reason=data.get("override_reason", ""),
            override_detail=data.get("override_detail", ""),
            issued_at=int(data.get("issued_at", 0)),
            args_digest=data.get("args_digest", ""),
        )


_DEFAULT_MAX_PENDING_ESCALATIONS = 100


class EscalationStore:
    """Store for pending escalations with expiry, background purge, and
    optional disk persistence.

    When ``persist_path`` is provided, pending escalations are saved to
    disk atomically (write-to-tmp then ``os.replace``) and reloaded on
    startup.  A background asyncio task purges expired entries
    periodically.
    """

    # Default per-tool escalation limit
    _DEFAULT_MAX_PER_TOOL = 10

    # Maximum persistence file size (10 MB) — prevents loading absurdly
    # large files that could DoS the gateway on startup.
    _MAX_PERSIST_FILE_SIZE = 10 * 1024 * 1024

    # Valid status values for loaded records
    _VALID_STATUSES = frozenset({"pending", "approved", "failed"})

    def __init__(
        self,
        timeout: float = _DEFAULT_ESCALATION_TIMEOUT,
        max_pending: int = _DEFAULT_MAX_PENDING_ESCALATIONS,
        persist_path: str | None = None,
        max_per_tool: int = _DEFAULT_MAX_PER_TOOL,
        secret: bytes | None = None,
    ) -> None:
        self._pending: dict[str, PendingEscalation] = {}
        self._timeout = timeout
        self._max_pending = max_pending
        self._max_per_tool = max_per_tool
        self._purge_task: _asyncio.Task | None = None
        self._lock = _asyncio.Lock()  # HIGH-03: async lock for all writes
        self._secret = secret  # gateway secret for record HMAC

        # Normalize persist path at init time so writes always go to a
        # well-known location (never CWD for filename-only paths).
        if persist_path:
            p = Path(persist_path)
            if not p.parent or p.parent == Path('.'):
                # Filename-only — relocate to safe default
                self._persist_path: str | None = str(
                    Path.home() / '.sanna' / 'escalations' / p.name
                )
            else:
                self._persist_path = str(p.expanduser().resolve())
        else:
            self._persist_path = None

        # Load any persisted escalations from disk
        if self._persist_path:
            self._load_from_disk()

    @property
    def timeout(self) -> float:
        return self._timeout

    @property
    def max_pending(self) -> int:
        return self._max_pending

    @property
    def persist_path(self) -> str | None:
        return self._persist_path

    # -- Background purge timer -----------------------------------------------

    async def start_purge_timer(
        self, interval_seconds: int = 60,
    ) -> None:
        """Start a background task to purge expired escalations."""
        async def _purge_loop() -> None:
            while True:
                await _asyncio.sleep(interval_seconds)
                try:
                    purged = self.purge_expired()
                    if purged:
                        logger.info(
                            "Purged %d expired escalation(s)", purged,
                        )
                    if self._persist_path:
                        await self._save_to_disk_async()
                except Exception:
                    logger.warning(
                        "Escalation purge/persist cycle failed",
                        exc_info=True,
                    )

        self._purge_task = _asyncio.create_task(_purge_loop())

    async def stop_purge_timer(self) -> None:
        """Cancel the background purge task."""
        if self._purge_task is not None:
            self._purge_task.cancel()
            try:
                await self._purge_task
            except _asyncio.CancelledError:
                pass
            self._purge_task = None

    # -- Disk persistence -----------------------------------------------------

    def _compute_record_hmac(self, record_dict: dict[str, Any]) -> str:
        """Compute HMAC-SHA256 over a serialized escalation record.

        The HMAC covers all fields except ``_record_hmac`` itself.
        Returns the hex digest. If no secret is configured, returns
        an empty string (persistence without integrity protection).
        """
        if not self._secret:
            return ""
        # Build a canonical copy without the hmac field
        clean = {k: v for k, v in record_dict.items() if k != "_record_hmac"}
        payload = json.dumps(clean, sort_keys=True).encode()
        return hmac.new(self._secret, payload, hashlib.sha256).hexdigest()

    def _save_to_disk(self) -> None:
        """Persist non-expired pending escalations to JSON file.

        Uses atomic_write_sync for symlink protection and crash safety.
        Path is already resolved at init time — no fallback logic needed.
        Each record includes a ``_record_hmac`` computed from the gateway
        secret for tamper detection on reload.
        """
        if not self._persist_path:
            return
        data = {}
        for eid, record in self._pending.items():
            if not self.is_expired(record):
                rd = record.to_dict()
                rd["_record_hmac"] = self._compute_record_hmac(rd)
                data[eid] = rd
        from sanna.utils.safe_io import atomic_write_sync, ensure_secure_dir
        persist_dir = Path(self._persist_path).parent
        ensure_secure_dir(persist_dir)
        atomic_write_sync(
            self._persist_path,
            json.dumps(data),
            mode=0o600,
        )

    def _validate_record_types(self, eid: str, data: dict) -> bool:
        """Validate field types of a deserialized escalation record.

        Returns True if the record passes all type checks, False otherwise.
        Logs a warning for each invalid field.
        """
        # Required string fields
        str_fields = [
            "escalation_id", "prefixed_name", "original_name",
            "server_name", "created_at",
        ]
        for f in str_fields:
            if f not in data or not isinstance(data[f], str):
                logger.warning(
                    "Skipping escalation %s: field '%s' missing or not a string",
                    eid, f,
                )
                return False

        # Status must be a known value
        status = data.get("status", "pending")
        if not isinstance(status, str) or status not in self._VALID_STATUSES:
            logger.warning(
                "Skipping escalation %s: invalid status '%s'",
                eid, status,
            )
            return False

        # Arguments must be a dict
        args = data.get("arguments", {})
        if not isinstance(args, dict):
            logger.warning(
                "Skipping escalation %s: 'arguments' is not a dict",
                eid,
            )
            return False

        # issued_at must be an int (or convertible to int)
        issued_at = data.get("issued_at", 0)
        if not isinstance(issued_at, (int, float)):
            logger.warning(
                "Skipping escalation %s: 'issued_at' is not numeric",
                eid,
            )
            return False

        # args_digest must be a string
        args_digest = data.get("args_digest", "")
        if not isinstance(args_digest, str):
            logger.warning(
                "Skipping escalation %s: 'args_digest' is not a string",
                eid,
            )
            return False

        return True

    def _load_from_disk(self) -> None:
        """Load pending escalations from disk, skipping expired.

        Security hardening (SEC-10):
        - Rejects symlinks at the persistence path
        - Enforces file permissions (max 0o640)
        - Enforces max file size (10 MB)
        - Validates record HMAC before accepting (SEC-5)
        - Validates field types strictly, skipping malformed records
        """
        if not self._persist_path or not os.path.exists(self._persist_path):
            return

        # FIX-3: Use O_NOFOLLOW to eliminate symlink TOCTOU race
        try:
            fd = os.open(str(self._persist_path), os.O_RDONLY | os.O_NOFOLLOW)
        except OSError as e:
            logger.warning("Cannot open escalation persistence file: %s", e)
            return

        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode):
                logger.warning("Escalation persistence path is not a regular file")
                return
            # FIX-44: Check permissions
            mode = st.st_mode
            if mode & (stat.S_IRWXG | stat.S_IRWXO):
                logger.warning(
                    "Escalation persistence file has insecure permissions: %o",
                    stat.S_IMODE(mode),
                )
            # SEC-10: Enforce max file size
            if st.st_size > self._MAX_PERSIST_FILE_SIZE:
                logger.warning(
                    "Refusing to load escalation store %s: "
                    "file size %d exceeds maximum %d bytes",
                    self._persist_path, st.st_size, self._MAX_PERSIST_FILE_SIZE,
                )
                return
            with os.fdopen(fd, 'r') as f:
                data = json.load(f)
            fd = -1  # fdopen took ownership
        except (json.JSONDecodeError, ValueError, OSError) as exc:
            logger.warning(
                "Failed to load escalation store from %s: %s",
                self._persist_path, exc,
            )
            return
        finally:
            if fd >= 0:
                os.close(fd)

        if not isinstance(data, dict):
            logger.warning(
                "Escalation store %s: expected JSON object at top level",
                self._persist_path,
            )
            return

        for eid, record_data in data.items():
            try:
                if not isinstance(record_data, dict):
                    logger.warning(
                        "Skipping escalation %s: record is not a dict", eid,
                    )
                    continue

                # SEC-5: Verify record HMAC before accepting
                if self._secret:
                    stored_hmac = record_data.get("_record_hmac", "")
                    if not stored_hmac or not isinstance(stored_hmac, str):
                        logger.warning(
                            "Skipping escalation %s: missing or invalid "
                            "_record_hmac",
                            eid,
                        )
                        continue
                    expected_hmac = self._compute_record_hmac(record_data)
                    if not hmac.compare_digest(stored_hmac, expected_hmac):
                        logger.warning(
                            "Skipping escalation %s: HMAC verification "
                            "failed (possible tampering)",
                            eid,
                        )
                        continue

                # SEC-10: Validate field types strictly
                if not self._validate_record_types(eid, record_data):
                    continue

                record = PendingEscalation.from_dict(record_data)
                if not self.is_expired(record):
                    self._pending[eid] = record
            except (KeyError, TypeError, ValueError) as exc:
                logger.warning(
                    "Skipping malformed escalation %s: %s", eid, exc,
                )

    # -- Async persistence wrapper --------------------------------------------

    def _write_snapshot_to_disk(self, snapshot: dict) -> None:
        """Write a pre-built snapshot dict to disk (runs in executor thread).

        Separated from ``_save_to_disk`` so the dict iteration happens
        in the event-loop thread (safe, single-threaded) and only the
        file I/O runs in the executor.  Each record already includes
        ``_record_hmac`` added during snapshotting.
        """
        from sanna.utils.safe_io import atomic_write_sync, ensure_secure_dir
        persist_dir = Path(self._persist_path).parent
        ensure_secure_dir(persist_dir)
        atomic_write_sync(
            self._persist_path,
            json.dumps(snapshot, indent=2),
            mode=0o600,
        )

    async def _save_to_disk_async(self) -> None:
        """Snapshot pending dict in event-loop thread, then write via executor.

        The snapshot is taken in the single-threaded event loop to avoid
        ``RuntimeError: dictionary changed size during iteration`` when
        the executor thread reads ``self._pending`` concurrently.
        Each record includes ``_record_hmac`` for tamper detection.
        """
        if not self._persist_path:
            return
        # Snapshot in the event loop thread (safe — single-threaded)
        snapshot = {}
        for eid, record in self._pending.items():
            if not self.is_expired(record):
                rd = record.to_dict()
                rd["_record_hmac"] = self._compute_record_hmac(rd)
                snapshot[eid] = rd
        loop = _asyncio.get_running_loop()
        await loop.run_in_executor(None, self._write_snapshot_to_disk, snapshot)

    # -- Core operations ------------------------------------------------------

    def purge_expired(self) -> int:
        """Remove all expired entries. Returns count purged."""
        expired_ids = [
            eid for eid, entry in self._pending.items()
            if self.is_expired(entry)
        ]
        for eid in expired_ids:
            del self._pending[eid]
        return len(expired_ids)

    def create(
        self,
        prefixed_name: str,
        original_name: str,
        arguments: dict[str, Any],
        server_name: str,
        reason: str,
    ) -> PendingEscalation:
        """Create and store a new pending escalation.

        Purges expired entries first. Raises ``RuntimeError`` if the
        store is at capacity after purging.
        """
        # Housekeeping: purge expired entries on every create
        self.purge_expired()

        # Enforce per-tool limit to prevent single-tool DoS
        tool_pending = sum(
            1 for e in self._pending.values()
            if e.prefixed_name == prefixed_name and e.status == "pending"
        )
        if tool_pending >= self._max_per_tool:
            raise RuntimeError(
                f"Too many pending escalations for tool "
                f"'{prefixed_name}' ({tool_pending}). "
                f"Approve or deny existing escalations first."
            )

        # Enforce global capacity limit
        if len(self._pending) >= self._max_pending:
            raise RuntimeError(
                f"Escalation store at capacity "
                f"({self._max_pending} pending). "
                f"Approve or deny existing escalations first."
            )

        esc_id = f"esc_{uuid.uuid4().hex}"
        now = int(_time_mod.time())
        args_digest = hashlib.sha256(
            json.dumps(arguments, sort_keys=True).encode(),
        ).hexdigest()
        entry = PendingEscalation(
            escalation_id=esc_id,
            prefixed_name=prefixed_name,
            original_name=original_name,
            arguments=copy.deepcopy(arguments),
            server_name=server_name,
            reason=reason,
            created_at=datetime.now(timezone.utc).isoformat(),
            issued_at=now,
            args_digest=args_digest,
        )
        self._pending[esc_id] = entry
        if self._persist_path:
            self._save_to_disk()
        return entry

    async def create_async(
        self,
        prefixed_name: str,
        original_name: str,
        arguments: dict[str, Any],
        server_name: str,
        reason: str,
    ) -> PendingEscalation:
        """Async wrapper: create in-memory + persist via executor.

        Preferred over :meth:`create` in async handlers to avoid
        blocking the event loop during file I/O.  Uses asyncio.Lock
        to prevent concurrent writes from corrupting state (HIGH-03).
        """
        async with self._lock:
            self.purge_expired()
            tool_pending = sum(
                1 for e in self._pending.values()
                if e.prefixed_name == prefixed_name and e.status == "pending"
            )
            if tool_pending >= self._max_per_tool:
                raise RuntimeError(
                    f"Too many pending escalations for tool "
                    f"'{prefixed_name}' ({tool_pending}). "
                    f"Approve or deny existing escalations first."
                )
            if len(self._pending) >= self._max_pending:
                raise RuntimeError(
                    f"Escalation store at capacity "
                    f"({self._max_pending} pending). "
                    f"Approve or deny existing escalations first."
                )
            esc_id = f"esc_{uuid.uuid4().hex}"
            now = int(_time_mod.time())
            args_digest = hashlib.sha256(
                json.dumps(arguments, sort_keys=True).encode(),
            ).hexdigest()
            entry = PendingEscalation(
                escalation_id=esc_id,
                prefixed_name=prefixed_name,
                original_name=original_name,
                arguments=copy.deepcopy(arguments),
                server_name=server_name,
                reason=reason,
                created_at=datetime.now(timezone.utc).isoformat(),
                issued_at=now,
                args_digest=args_digest,
            )
            self._pending[esc_id] = entry
            await self._save_to_disk_async()
            return entry

    def get(self, escalation_id: str) -> PendingEscalation | None:
        """Get a pending escalation, or None if not found."""
        return self._pending.get(escalation_id)

    def is_expired(self, entry: PendingEscalation) -> bool:
        """Check if an escalation entry has expired."""
        created = datetime.fromisoformat(
            entry.created_at.replace("Z", "+00:00"),
        )
        if created.tzinfo is None:
            created = created.replace(tzinfo=timezone.utc)
        elapsed = (datetime.now(timezone.utc) - created).total_seconds()
        return elapsed > self._timeout

    def remove(self, escalation_id: str) -> PendingEscalation | None:
        """Remove and return a pending escalation."""
        entry = self._pending.pop(escalation_id, None)
        if entry is not None and self._persist_path:
            self._save_to_disk()
        return entry

    async def remove_async(self, escalation_id: str) -> PendingEscalation | None:
        """Async wrapper: remove + persist via executor.

        Preferred over :meth:`remove` in async handlers to avoid
        blocking the event loop during file I/O.  Uses asyncio.Lock (HIGH-03).
        """
        async with self._lock:
            entry = self._pending.pop(escalation_id, None)
            if entry is not None:
                await self._save_to_disk_async()
            return entry

    def mark_status(
        self, escalation_id: str, status: str,
    ) -> PendingEscalation | None:
        """Update the status of a pending escalation in-place."""
        entry = self._pending.get(escalation_id)
        if entry is not None:
            entry.status = status
            if self._persist_path:
                self._save_to_disk()
        return entry

    async def mark_status_async(
        self, escalation_id: str, status: str,
    ) -> PendingEscalation | None:
        """Async wrapper: mark_status + persist via executor.

        Preferred over :meth:`mark_status` in async handlers to avoid
        blocking the event loop during file I/O.  Uses asyncio.Lock (HIGH-03).
        """
        async with self._lock:
            entry = self._pending.get(escalation_id)
            if entry is not None:
                entry.status = status
                await self._save_to_disk_async()
            return entry

    def __len__(self) -> int:
        return len(self._pending)

    def clear(self) -> None:
        self._pending.clear()
        if self._persist_path:
            self._save_to_disk()


# ---------------------------------------------------------------------------
# SannaGateway
# ---------------------------------------------------------------------------

class SannaGateway:
    """MCP gateway that proxies tools from one or more downstream MCP servers.

    Discovers downstream tools on startup, re-exposes them under
    ``{server_name}_{tool_name}`` prefixed names, and forwards all
    ``tools/call`` requests transparently.

    When a constitution is configured, every tool call is evaluated
    against authority boundaries and generates a signed receipt.

    Tools matching ``must_escalate`` are held pending until the user
    approves or denies via the ``sanna_approve_escalation`` /
    ``sanna_deny_escalation`` meta-tools.

    Supports two construction modes:

    **Single-downstream (v0.10.0 compatible):**

        gw = SannaGateway(
            server_name="notion",
            command="npx",
            args=["-y", "@notionhq/notion-mcp-server"],
            constitution_path="constitution.yaml",
            signing_key_path="gateway.key",
        )

    **Multi-downstream:**

        gw = SannaGateway(
            downstreams=[
                DownstreamSpec(name="notion", command="npx", ...),
                DownstreamSpec(name="github", command="npx", ...),
            ],
            constitution_path="constitution.yaml",
            signing_key_path="gateway.key",
        )
    """

    def __init__(
        self,
        server_name: str | None = None,
        command: str | None = None,
        args: list[str] | None = None,
        env: dict[str, str] | None = None,
        timeout: float = 30.0,
        # Multi-downstream
        downstreams: list[DownstreamSpec] | None = None,
        # Block C: enforcement
        constitution_path: str | None = None,
        signing_key_path: str | None = None,
        constitution_public_key_path: str | None = None,
        policy_overrides: dict[str, str] | None = None,
        default_policy: str | None = None,
        # Block E: escalation
        escalation_timeout: float = _DEFAULT_ESCALATION_TIMEOUT,
        max_pending_escalations: int = _DEFAULT_MAX_PENDING_ESCALATIONS,
        # Block F: hardening
        receipt_store_path: str | None = None,
        circuit_breaker_cooldown: float = _DEFAULT_CIRCUIT_BREAKER_COOLDOWN,
        # Approval token enforcement
        require_approval_token: bool = True,
        # Block E v2: escalation hardening
        gateway_secret_path: str | None = None,
        escalation_persist_path: str | None = None,
        approval_requires_reason: bool = False,
        token_delivery: list[str] | None = None,
        # Block H: constitution signature verification
        require_constitution_sig: bool = True,
        # Block G: PII redaction
        redaction_config: Any = None,
    ) -> None:
        # Build downstream specs — either from explicit list or legacy params
        if downstreams is not None:
            # Guard: per-downstream config must be set on DownstreamSpec, not
            # as gateway-level kwargs, when using the downstreams list.
            _ds_only = {
                "policy_overrides": policy_overrides,
                "default_policy": default_policy,
            }
            _ds_conflicts = [k for k, v in _ds_only.items() if v is not None]
            if circuit_breaker_cooldown != _DEFAULT_CIRCUIT_BREAKER_COOLDOWN:
                _ds_conflicts.append("circuit_breaker_cooldown")
            if _ds_conflicts:
                raise ValueError(
                    f"{', '.join(_ds_conflicts)} must be set on "
                    f"DownstreamSpec when using downstreams list, "
                    f"not as gateway-level kwargs"
                )
            if len(downstreams) == 0:
                raise ValueError(
                    "downstreams list must contain at least one entry"
                )
            self._downstream_states: dict[str, _DownstreamState] = {}
            import re as _re
            for spec in downstreams:
                if not _re.match(r'^[a-zA-Z0-9_-]+$', spec.name):
                    raise ValueError(
                        f"Downstream name '{spec.name}' contains invalid "
                        f"characters. Use alphanumeric, hyphens, and "
                        f"underscores only."
                    )
                if spec.name in self._downstream_states:
                    raise ValueError(
                        f"Duplicate downstream name: {spec.name}"
                    )
                self._downstream_states[spec.name] = _DownstreamState(
                    spec=spec,
                )
        elif server_name is not None and command is not None:
            # Legacy single-downstream constructor — use downstreams= or for_single_server()
            import warnings as _warnings
            _warnings.warn(
                "Passing server_name/command directly to SannaGateway() is deprecated. "
                "Use SannaGateway(downstreams=[DownstreamSpec(...)]) or "
                "SannaGateway.for_single_server() instead.",
                DeprecationWarning,
                stacklevel=2,
            )
            import re as _re
            if not _re.match(r'^[a-zA-Z0-9_-]+$', server_name):
                raise ValueError(
                    f"server_name '{server_name}' contains invalid "
                    f"characters. Use alphanumeric, hyphens, and "
                    f"underscores only."
                )
            spec = DownstreamSpec(
                name=server_name,
                command=command,
                args=args or [],
                env=env,
                timeout=timeout,
                policy_overrides=policy_overrides or {},
                default_policy=default_policy,
                circuit_breaker_cooldown=circuit_breaker_cooldown,
            )
            self._downstream_states = {
                server_name: _DownstreamState(spec=spec),
            }
        else:
            raise ValueError(
                "Either 'downstreams' list or 'server_name' + 'command' "
                "required"
            )

        # Unified tool routing: prefixed_name → downstream_name
        self._tool_to_downstream: dict[str, str] = {}
        # Unified tool map: prefixed_name → original_name (backward compat)
        self._tool_map: dict[str, str] = {}

        self._server = Server("sanna_gateway")

        # Block C: enforcement state (gateway-level, shared by all downstreams)
        self._constitution_path = constitution_path
        self._signing_key_path = signing_key_path
        self._constitution_public_key_path = constitution_public_key_path
        self._require_constitution_sig = require_constitution_sig
        self._constitution: Any = None
        self._constitution_ref: dict | None = None
        self._check_configs: list | None = None
        self._custom_records: list | None = None
        self._last_receipt: dict | None = None

        # Block G: reasoning evaluator (set in start() after constitution loads)
        self._reasoning_evaluator: Any = None

        # Approval token: HMAC-bound human verification
        # Load secret BEFORE creating escalation store so it can be used
        # for record HMAC verification on disk load.
        self._require_approval_token = require_approval_token
        self._gateway_secret = self._load_or_create_secret(gateway_secret_path)

        # Block E: escalation state — pass gateway secret for record HMAC
        self._escalation_store = EscalationStore(
            timeout=escalation_timeout,
            max_pending=max_pending_escalations,
            persist_path=escalation_persist_path,
            secret=self._gateway_secret,
        )
        self._approval_requires_reason = approval_requires_reason
        self._token_delivery = token_delivery or ["stderr"]
        self._approval_webhook_url: str = ""
        self._token_expiry_seconds: int = 900

        # Block F: hardening state
        self._receipt_store_path = receipt_store_path

        # Block G: PII redaction
        from sanna.gateway.config import RedactionConfig
        self._redaction_config = redaction_config or RedactionConfig()
        if self._redaction_config.enabled:
            logger.info(
                "Redaction enabled. Only redacted receipts will be "
                "persisted to disk. The signature covers the original "
                "unredacted content (held in memory only).",
            )

        self._setup_handlers()

    # -- Factory methods -------------------------------------------------------

    @classmethod
    def for_single_server(
        cls,
        name: str,
        command: str,
        *,
        args: list[str] | None = None,
        env: dict[str, str] | None = None,
        timeout: float = 30.0,
        policy_overrides: dict[str, str] | None = None,
        default_policy: str | None = None,
        circuit_breaker_cooldown: float = _DEFAULT_CIRCUIT_BREAKER_COOLDOWN,
        **kwargs,
    ) -> "SannaGateway":
        """Create a gateway with a single downstream server.

        Preferred over passing ``server_name``/``command`` directly, which
        emits a :class:`DeprecationWarning`.

        Parameters
        ----------
        name:
            Human-readable identifier for the downstream server.
        command:
            Executable to launch.
        args:
            Additional CLI args for the command.
        env:
            Extra environment variables for the child process.
        timeout:
            Per-call timeout in seconds.
        policy_overrides:
            Per-tool policy overrides for this downstream server.
        default_policy:
            Default policy for tools not listed in *policy_overrides*.
        circuit_breaker_cooldown:
            Seconds before retrying after circuit breaker opens.
        **kwargs:
            All remaining keyword arguments are forwarded to
            :class:`SannaGateway.__init__` (constitution_path, signing_key_path,
            etc.).
        """
        spec = DownstreamSpec(
            name=name,
            command=command,
            args=args or [],
            env=env,
            timeout=timeout,
            policy_overrides=policy_overrides or {},
            default_policy=default_policy,
            circuit_breaker_cooldown=circuit_breaker_cooldown,
        )
        return cls(downstreams=[spec], **kwargs)

    # -- Secret management ----------------------------------------------------

    @staticmethod
    def _load_or_create_secret(
        secret_path: str | None = None,
    ) -> bytes:
        """Load gateway HMAC secret from file, or create and persist one.

        Resolution order:
        1. ``SANNA_GATEWAY_SECRET`` env var (hex-encoded) — for containers
        2. File at ``secret_path`` (or ``~/.sanna/gateway_secret``)
        3. Generate new random secret and persist to file

        Security: validates the secret is exactly 32 bytes. Uses
        ``ensure_secure_dir`` for the ``~/.sanna`` directory and
        ``atomic_write_sync`` for crash-safe, symlink-protected writes.
        """
        from sanna.utils.safe_io import (
            SecurityError as SafeIOSecurityError,
            atomic_write_sync,
            ensure_secure_dir,
        )

        # 1. Env var override (hex-encoded)
        env_secret = os.environ.get("SANNA_GATEWAY_SECRET")
        if env_secret:
            try:
                decoded = bytes.fromhex(env_secret)
                if len(decoded) != 32:
                    raise SafeIOSecurityError(
                        f"SANNA_GATEWAY_SECRET must be exactly 32 bytes, "
                        f"got {len(decoded)}",
                    )
                return decoded
            except ValueError:
                logger.warning(
                    "SANNA_GATEWAY_SECRET is not valid hex, ignoring",
                )

        # 2. Load from file — FIX-17: O_NOFOLLOW eliminates symlink TOCTOU
        path = secret_path or os.path.expanduser("~/.sanna/gateway_secret")
        if os.path.exists(path):
            try:
                fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
            except OSError as e:
                raise SafeIOSecurityError(
                    f"Cannot open gateway secret at {path}: {e}"
                )
            try:
                st = os.fstat(fd)
                if not stat.S_ISREG(st.st_mode):
                    raise SafeIOSecurityError(
                        f"Gateway secret at {path} is not a regular file"
                    )
                secret = os.read(fd, 33)  # read 1 extra byte for length check
            finally:
                os.close(fd)
            if len(secret) != 32:
                raise SafeIOSecurityError(
                    f"Gateway secret at {path} must be exactly 32 bytes, "
                    f"got {len(secret)}",
                )
            return secret

        # 3. Create new secret and persist
        secret = os.urandom(32)
        sanna_dir = os.path.dirname(path)
        ensure_secure_dir(sanna_dir)
        atomic_write_sync(path, secret, mode=0o600)
        logger.info("Created gateway secret at %s", path)
        return secret

    # -- backward-compat helpers for single-downstream tests -----------------

    @property
    def _first_ds(self) -> _DownstreamState:
        """First (or only) downstream state — for backward compat."""
        return next(iter(self._downstream_states.values()))

    # These properties let existing tests that directly set/get internal
    # circuit breaker fields continue working for single-downstream gateways.

    @property
    def _circuit_state(self) -> CircuitState:
        return self._first_ds.circuit_state

    @_circuit_state.setter
    def _circuit_state(self, value: CircuitState) -> None:
        self._first_ds.circuit_state = value

    @property
    def _circuit_opened_at(self) -> datetime | None:
        return self._first_ds.circuit_opened_at

    @_circuit_opened_at.setter
    def _circuit_opened_at(self, value: datetime | None) -> None:
        self._first_ds.circuit_opened_at = value

    @property
    def _consecutive_failures(self) -> int:
        return self._first_ds.consecutive_failures

    @_consecutive_failures.setter
    def _consecutive_failures(self, value: int) -> None:
        self._first_ds.consecutive_failures = value

    @property
    def _circuit_breaker_cooldown(self) -> float:
        return self._first_ds.spec.circuit_breaker_cooldown

    @property
    def _downstream(self) -> DownstreamConnection | None:
        return self._first_ds.connection

    @_downstream.setter
    def _downstream(self, value: DownstreamConnection | None) -> None:
        self._first_ds.connection = value

    # -- public properties ---------------------------------------------------

    @property
    def server_name(self) -> str:
        """Name of the first (or only) downstream server."""
        return self._first_ds.spec.name

    @property
    def downstream(self) -> DownstreamConnection | None:
        """The first downstream connection, or ``None`` before start."""
        return self._first_ds.connection

    @property
    def downstream_states(self) -> dict[str, _DownstreamState]:
        """Per-downstream runtime states (read-only view)."""
        return dict(self._downstream_states)

    @property
    def tool_map(self) -> dict[str, str]:
        """Mapping of prefixed gateway tool names to original names."""
        return dict(self._tool_map)

    @property
    def constitution(self) -> Any:
        """The loaded constitution, or ``None``."""
        return self._constitution

    @property
    def last_receipt(self) -> dict | None:
        """The most recently generated receipt."""
        return self._last_receipt

    @property
    def escalation_store(self) -> EscalationStore:
        """The pending escalation store."""
        return self._escalation_store

    @property
    def healthy(self) -> bool:
        """Whether all downstreams are healthy (circuit CLOSED)."""
        return all(
            ds.circuit_state == CircuitState.CLOSED
            for ds in self._downstream_states.values()
        )

    @property
    def circuit_state(self) -> CircuitState:
        """Circuit state of the first downstream."""
        return self._first_ds.circuit_state

    @property
    def consecutive_failures(self) -> int:
        """Consecutive failure count of the first downstream."""
        return self._first_ds.consecutive_failures

    @property
    def require_approval_token(self) -> bool:
        """Whether HMAC approval tokens are required for escalations."""
        return self._require_approval_token

    # -- approval token computation ------------------------------------------

    def _compute_approval_token(self, entry: PendingEscalation) -> str:
        """Compute the HMAC-SHA256 approval token for an escalation.

        The token binds the escalation to specific parameters so it
        cannot be replayed across different escalations.

        Uses ``args_digest`` and ``issued_at`` when available (v0.13.1+)
        for deterministic re-derivation after restart. Falls back to
        re-computing from ``arguments`` and ``created_at`` for backward
        compatibility with older records.

        Token = HMAC-SHA256(gateway_secret,
            escalation_id || tool_name || args_digest || issued_at)

        Returns the token as a hex string.
        """
        # Use pre-computed args_digest if available, else derive from arguments
        if entry.args_digest:
            args_hash = entry.args_digest
        else:
            args_hash = hashlib.sha256(
                json.dumps(entry.arguments, sort_keys=True).encode(),
            ).hexdigest()

        # Use issued_at (integer epoch) if available, else fall back to created_at
        if entry.issued_at:
            timestamp_part = str(entry.issued_at)
        else:
            timestamp_part = entry.created_at

        message = (
            f"{entry.escalation_id}|{entry.original_name}|"
            f"{args_hash}|{timestamp_part}"
        )
        return hmac.new(
            self._gateway_secret,
            message.encode(),
            hashlib.sha256,
        ).hexdigest()

    @staticmethod
    def _hash_token(token: str) -> str:
        """SHA-256 hash of a token for storage and receipts."""
        return hashlib.sha256(token.encode()).hexdigest()

    def _deliver_token(
        self,
        entry: PendingEscalation,
        token: str,
    ) -> None:
        """Deliver an approval token via configured delivery mechanisms."""
        import time as _time
        ttl = int(self._escalation_store.timeout)
        token_info = {
            "escalation_id": entry.escalation_id,
            "token": token,
            "tool_name": entry.prefixed_name,
            "timestamp": entry.created_at,
            "ttl_remaining": ttl,
            "expires_at": _time.time() + ttl,
        }
        for method in self._token_delivery:
            if method == "stderr":
                print(
                    f"[SANNA] Approval token for escalation "
                    f"{entry.escalation_id}: {token}",
                    file=sys.stderr,
                    flush=True,
                )
                print(
                    "[SANNA] Provide this token to approve the "
                    "action.",
                    file=sys.stderr,
                    flush=True,
                )
            elif method == "file":
                print(
                    "[SANNA] WARNING: Writing approval token to file. "
                    "File-based token delivery is insecure — agents "
                    "with file-reading tools can self-approve.",
                    file=sys.stderr,
                    flush=True,
                )
                self._deliver_token_to_file(token_info)
            elif method == "webhook":
                self._deliver_token_via_webhook(entry, token_info)
            elif method == "log":
                logger.info(
                    "Escalation %s requires approval. Token: %s",
                    entry.escalation_id,
                    token,
                )
            elif method == "callback":
                # Reserved for user-registered callbacks
                logger.debug(
                    "Callback token delivery not yet configured "
                    "for %s",
                    entry.escalation_id,
                )

    #: Maximum number of tokens retained in the pending tokens file.
    _MAX_PENDING_TOKENS = 1000

    def _deliver_token_to_file(
        self, token_info: dict[str, Any],
    ) -> None:
        """Write token info to ~/.sanna/pending_tokens.json.

        Security and reliability guarantees:

        * **File locking** via ``filelock`` prevents race conditions when
          multiple concurrent escalations write at the same time.
        * **TTL pruning** — tokens with an ``expires_at`` timestamp in the
          past are removed on every write.
        * **Size cap** — at most ``_MAX_PENDING_TOKENS`` entries are kept;
          the oldest are dropped if the cap is exceeded.
        * **Atomic write** via ``atomic_write_sync`` for symlink protection
          and crash safety.
        """
        import time as _time
        from filelock import FileLock
        from sanna.utils.safe_io import atomic_write_sync, ensure_secure_dir

        tokens_path = os.path.expanduser(
            "~/.sanna/pending_tokens.json",
        )
        ensure_secure_dir(os.path.dirname(tokens_path))

        lock = FileLock(tokens_path + ".lock", timeout=10)
        with lock:
            # Load existing tokens
            existing: list[dict] = []
            if os.path.exists(tokens_path):
                try:
                    from sanna.utils.safe_json import safe_json_load
                    with open(tokens_path) as f:
                        existing = safe_json_load(f)
                    if not isinstance(existing, list):
                        existing = []
                except (json.JSONDecodeError, ValueError, OSError):
                    existing = []

            existing.append(token_info)

            # Prune expired tokens (use expires_at if present)
            now = _time.time()
            existing = [
                t for t in existing
                if t.get("expires_at", now + 1) > now
            ]

            # Enforce size cap — drop oldest entries beyond the limit
            cap = self._MAX_PENDING_TOKENS
            if len(existing) > cap:
                dropped = len(existing) - cap
                existing = existing[-cap:]
                logger.warning(
                    "Pending token store exceeded %d entries; "
                    "oldest %d tokens pruned",
                    cap, dropped,
                )

            # Atomic write with symlink protection
            atomic_write_sync(
                tokens_path,
                json.dumps(existing, indent=2),
                mode=0o600,
            )

    def _deliver_token_via_webhook(
        self,
        entry: PendingEscalation,
        token_info: dict[str, Any],
    ) -> None:
        """POST approval token to the configured webhook URL.

        Uses stdlib urllib to avoid adding httpx as a required dependency.
        Logs warnings on failure but does not raise — webhook delivery is
        best-effort so other delivery methods can still succeed.
        """
        if not self._approval_webhook_url:
            logger.warning(
                "Webhook delivery configured but no "
                "approval_webhook_url set for %s",
                entry.escalation_id,
            )
            return

        import urllib.request
        import urllib.error

        expires_at_iso = datetime.fromtimestamp(
            token_info["expires_at"], tz=timezone.utc,
        ).isoformat()

        payload = {
            "escalation_id": entry.escalation_id,
            "tool_name": entry.prefixed_name,
            "reason": entry.reason,
            "token": token_info["token"],
            "expires_at": expires_at_iso,
            "approve_command": (
                f"sanna-approve --escalation-id {entry.escalation_id} "
                f"--token <TOKEN>"
            ),
        }

        body = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            self._approval_webhook_url,
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        # SEC-7 / FIX-8: Disable ALL redirect following to prevent token
        # leak via open-redirect chains.  Covers every standard redirect
        # status: 301 (Moved Permanently), 302 (Found), 303 (See Other),
        # 307 (Temporary Redirect), 308 (Permanent Redirect).
        #
        # We RAISE instead of returning None.  Returning None from
        # redirect_request() is ambiguous in urllib — it means "I didn't
        # handle this, try another handler".  Raising HTTPError makes the
        # rejection unambiguous and ensures no redirect can slip through
        # regardless of handler ordering or future urllib changes.
        class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
            """Reject ALL HTTP redirects (301, 302, 303, 307, 308).

            Raises ``HTTPError`` unconditionally so no redirect chain can
            be followed — not even the first hop.  This prevents token
            leakage via open-redirect attacks where the initial URL is
            trusted but redirects to an attacker-controlled host.
            """

            def redirect_request(
                self, req, fp, code, msg, headers, newurl,
            ):
                logger.warning(
                    "Webhook for %s received redirect (%d) to %s — "
                    "blocked. Webhook URLs must be direct (no redirects).",
                    entry.escalation_id,
                    code,
                    newurl,
                )
                raise urllib.error.HTTPError(
                    req.full_url,
                    code,
                    f"Redirect to {newurl} blocked by security policy",
                    headers,
                    fp,
                )

        opener = urllib.request.build_opener(_NoRedirectHandler)

        # FIX-1: Re-validate webhook URL at send time to prevent DNS rebinding.
        # An attacker can change DNS records between config validation and send.
        try:
            from sanna.gateway.config import validate_webhook_url
            validate_webhook_url(self._approval_webhook_url)
        except Exception as exc:
            logger.warning(
                "Webhook URL re-validation failed for %s: %s — not sending",
                entry.escalation_id,
                exc,
            )
            return

        # FIX-13: Maximum response body size to prevent memory exhaustion
        # from a malicious webhook endpoint returning a multi-GB response.
        _MAX_WEBHOOK_RESPONSE_BYTES = 1024 * 1024  # 1 MB

        try:
            with opener.open(req, timeout=10) as resp:
                # FIX-13: Read response body with a size limit.  We must
                # consume (and discard) the body to release the connection,
                # but we bound the read to prevent memory exhaustion.
                resp.read(_MAX_WEBHOOK_RESPONSE_BYTES)
                if resp.status >= 400:
                    logger.warning(
                        "Webhook delivery for %s returned HTTP %d",
                        entry.escalation_id,
                        resp.status,
                    )
        except urllib.error.HTTPError as exc:
            # Redirect responses (3xx) now surface as HTTPError because
            # _NoRedirectHandler raises instead of returning None.
            if 300 <= exc.code < 400:
                logger.warning(
                    "Webhook delivery for %s: redirect %d blocked",
                    entry.escalation_id,
                    exc.code,
                )
            else:
                logger.warning(
                    "Webhook delivery for %s returned HTTP %d",
                    entry.escalation_id,
                    exc.code,
                )
        except urllib.error.URLError as exc:
            logger.warning(
                "Webhook delivery failed for %s: %s",
                entry.escalation_id,
                exc,
            )
        except Exception as exc:
            logger.warning(
                "Webhook delivery error for %s: %s",
                entry.escalation_id,
                exc,
            )

    # -- handler registration ------------------------------------------------

    def _setup_handlers(self) -> None:
        """Register ``list_tools`` and ``call_tool`` handlers on the
        low-level MCP server."""
        gateway = self

        @self._server.list_tools()
        async def handle_list_tools() -> list[types.Tool]:
            return gateway._build_tool_list()

        @self._server.call_tool()
        async def handle_call_tool(
            name: str, arguments: dict[str, Any] | None,
        ) -> types.CallToolResult:
            return await gateway._forward_call(name, arguments)

    # -- lifecycle -----------------------------------------------------------

    async def start(self) -> None:
        """Connect to all downstreams, discover tools, load constitution.

        Raises:
            DownstreamConnectionError: If a downstream server cannot be
                started or the MCP handshake fails.
            SannaConstitutionError: If the constitution is not signed.
        """
        for ds_state in self._downstream_states.values():
            spec = ds_state.spec
            ds_state.connection = DownstreamConnection(
                command=spec.command,
                args=spec.args,
                env=spec.env,
                timeout=spec.timeout,
            )
            try:
                await ds_state.connection.connect()
            except Exception as e:
                if spec.optional:
                    logger.warning(
                        "Optional downstream '%s' failed to connect: "
                        "%s. Continuing without it.",
                        spec.name, e,
                    )
                    ds_state.connection = None
                    continue
                raise

            for tool in ds_state.connection.tools:
                prefixed = f"{spec.name}_{tool['name']}"
                if prefixed in self._tool_to_downstream:
                    existing_ds = self._tool_to_downstream[prefixed]
                    raise DuplicateToolError(
                        f"Tool '{prefixed}' already registered by "
                        f"downstream '{existing_ds}'. Cannot register "
                        f"duplicate from '{spec.name}'. Use distinct "
                        f"tool names or configure tool name prefixing."
                    )
                ds_state.tool_map[prefixed] = tool["name"]
                self._tool_map[prefixed] = tool["name"]
                self._tool_to_downstream[prefixed] = spec.name

            tool_names = sorted(ds_state.tool_map.keys())
            logger.info(
                "Downstream '%s' connected: %d tools (%s)",
                spec.name,
                len(tool_names),
                ", ".join(tool_names[:10]) + ("..." if len(tool_names) > 10 else ""),
            )

        # Block C: load constitution if configured
        if self._constitution_path is not None:
            from sanna.constitution import (
                load_constitution,
                constitution_to_receipt_ref,
                SannaConstitutionError,
            )
            from sanna.enforcement import configure_checks
            from sanna.utils.crypto_validation import is_valid_signature_structure

            self._constitution = load_constitution(self._constitution_path)
            if not self._constitution.policy_hash:
                raise SannaConstitutionError(
                    f"Constitution has no policy hash (not hashed or signed): "
                    f"{self._constitution_path}. "
                    f"Run: sanna-sign-constitution {self._constitution_path}"
                )

            # Resolve public key from env var if not explicitly configured
            if not self._constitution_public_key_path:
                _env_key = os.environ.get("SANNA_CONSTITUTION_PUBLIC_KEY")
                if _env_key and os.path.isfile(_env_key):
                    try:
                        from sanna.crypto import load_public_key, compute_key_id
                        _env_pub = load_public_key(_env_key)
                        _env_key_id = compute_key_id(_env_pub)
                        _const_sig = self._constitution.provenance.signature if self._constitution.provenance else None
                        if _const_sig and getattr(_const_sig, 'key_id', None) == _env_key_id:
                            self._constitution_public_key_path = _env_key
                    except Exception:
                        pass

            # Reject constitutions that are hashed but not Ed25519-signed (always enforced)
            _sig = self._constitution.provenance.signature if self._constitution.provenance else None
            _has_structural_sig = is_valid_signature_structure(_sig)
            if not _has_structural_sig:
                raise SannaConstitutionError(
                    f"Constitution signature is missing or malformed: "
                    f"{self._constitution_path}. Sign with: "
                    f"sanna-sign-constitution {self._constitution_path} --private-key <key>"
                )

            _sig_verified = None

            if self._require_constitution_sig:
                # Strict mode: require public key and cryptographic verification
                if not self._constitution_public_key_path:
                    raise SannaConstitutionError(
                        f"Constitution has signature but no public key "
                        f"configured to verify it. Provide "
                        f"constitution_public_key_path or set "
                        f"require_constitution_sig=False for local development."
                    )
                self._verify_constitution_signature()
                _sig_verified = True
            else:
                # Permissive mode: verify if we can, warn otherwise
                if self._constitution_public_key_path:
                    self._verify_constitution_signature()
                    _sig_verified = True
                else:
                    logger.warning(
                        "Constitution signature present but no public key "
                        "configured to verify it: %s",
                        self._constitution_path,
                    )
                    _sig_verified = False

            self._constitution_ref = constitution_to_receipt_ref(
                self._constitution,
            )
            # Add signature_verified to constitution_ref
            if _sig_verified is not None:
                self._constitution_ref["signature_verified"] = _sig_verified

            self._check_configs, self._custom_records = configure_checks(
                self._constitution,
            )

            logger.info(
                "Constitution loaded: hash=%s, invariants=%d, checks=%d",
                self._constitution.policy_hash[:16],
                len(self._constitution.invariants),
                len(self._check_configs),
            )

            # Block G: Initialize reasoning evaluator if configured
            self._reasoning_evaluator = None
            if self._constitution.reasoning:
                from sanna.reasoning import ReasoningEvaluator

                self._reasoning_evaluator = ReasoningEvaluator(
                    self._constitution,
                )
                logger.info("Reasoning evaluator initialized")

        # Start escalation purge timer
        await self._escalation_store.start_purge_timer()

        logger.info(
            "Gateway started: %d tools from %d downstream(s)",
            len(self._tool_map),
            len(self._downstream_states),
        )

    def _verify_constitution_signature(self) -> None:
        """Verify constitution Ed25519 signature against configured public key.

        Called during startup when ``constitution_public_key_path`` is set.
        Raises ``SannaConstitutionError`` if the signature is missing,
        invalid, or doesn't match the public key.
        """
        from sanna.constitution import SannaConstitutionError
        from sanna.crypto import verify_constitution_full

        key_path = self._constitution_public_key_path
        sig = self._constitution.provenance.signature

        if sig is None or not sig.value:
            raise SannaConstitutionError(
                "Constitution signature verification failed: "
                "constitution has no Ed25519 signature but "
                f"constitution_public_key is configured ({key_path}). "
                "Sign the constitution with: "
                f"sanna-sign-constitution {self._constitution_path}"
            )

        valid = verify_constitution_full(self._constitution, key_path)
        if not valid:
            raise SannaConstitutionError(
                "Constitution signature verification failed. "
                "The constitution may have been tampered with. "
                f"Public key: {key_path}"
            )

        logger.info(
            "Constitution signature verified against %s", key_path,
        )

    async def shutdown(self) -> None:
        """Disconnect from all downstream servers and clean up."""
        await self._escalation_store.stop_purge_timer()
        for ds_state in self._downstream_states.values():
            if ds_state.connection is not None:
                await ds_state.connection.close()
                ds_state.connection = None
            ds_state.tool_map.clear()
        self._tool_map.clear()
        self._tool_to_downstream.clear()
        self._constitution = None
        self._constitution_ref = None
        self._check_configs = None
        self._custom_records = None
        self._reasoning_evaluator = None
        self._escalation_store.clear()

    async def run_stdio(self) -> None:
        """Start the gateway, serve on stdio, and shut down on exit."""
        await self.start()
        try:
            async with stdio_server() as (read_stream, write_stream):
                await self._server.run(
                    read_stream,
                    write_stream,
                    self._server.create_initialization_options(),
                )
        finally:
            await self.shutdown()

    # -- tool list -----------------------------------------------------------

    def _build_tool_list(self) -> list[types.Tool]:
        """Build the gateway's tool list from discovered downstream tools
        plus gateway meta-tools."""
        tools: list[types.Tool] = []
        for ds_state in self._downstream_states.values():
            if ds_state.connection is None:
                continue
            for tool_dict in ds_state.connection.tools:
                prefixed = f"{ds_state.spec.name}_{tool_dict['name']}"
                # Block G: mutate schema to add _justification if required
                effective_dict = tool_dict
                if (
                    self._reasoning_evaluator
                    and self._constitution
                ):
                    from sanna.gateway.schema_mutation import (
                        mutate_tool_schema,
                    )

                    effective_dict = mutate_tool_schema(
                        tool_dict,
                        self._constitution,
                        ds_state.spec.policy_overrides,
                        ds_state.spec.default_policy,
                    )
                tools.append(_dict_to_tool(prefixed, effective_dict))

        # Block E: add gateway meta-tools (not prefixed)
        tools.extend(_build_meta_tools())
        return tools

    # -- downstream lookup ---------------------------------------------------

    def _get_ds_for_tool(
        self, prefixed_name: str,
    ) -> tuple[_DownstreamState, str] | None:
        """Look up the downstream and original name for a prefixed tool.

        Returns ``(ds_state, original_name)`` or ``None`` if not found.
        """
        ds_name = self._tool_to_downstream.get(prefixed_name)
        if ds_name is None:
            return None
        ds_state = self._downstream_states.get(ds_name)
        if ds_state is None:
            return None
        original = ds_state.tool_map.get(prefixed_name)
        if original is None:
            return None
        return ds_state, original

    # -- policy resolution ---------------------------------------------------

    def _resolve_policy(
        self, original_name: str, ds_state: _DownstreamState,
    ) -> str | None:
        """Resolve per-tool policy override for a specific downstream.

        Priority:
            1. Per-tool override in ``ds_state.spec.policy_overrides``
            2. Restrictive ``ds_state.spec.default_policy``
            3. ``None`` — fall through to constitution evaluation

        Returns ``"can_execute"``, ``"cannot_execute"``, or
        ``"must_escalate"``, or ``None`` to fall through.
        """
        # 1. Per-tool override — always wins (explicit intent)
        override = ds_state.spec.policy_overrides.get(original_name)
        if override is not None:
            return override

        # 2. Restrictive default_policy takes effect as a server-level guard
        dp = ds_state.spec.default_policy
        if dp is not None and dp != "can_execute":
            return dp

        # 3. No override — fall through to constitution evaluation
        return None

    # -- crash recovery & circuit breaker (Block F) --------------------------

    async def _after_downstream_call(
        self,
        tool_result: types.CallToolResult,
        ds_state: _DownstreamState,
        *,
        is_probe: bool = False,
    ) -> types.CallToolResult:
        """Post-call hook: track per-downstream failures and recovery.

        Counts consecutive connection-level errors. On the first
        error, attempts ONE restart. After threshold consecutive
        failures, opens the circuit breaker for this downstream.
        """
        if ds_state.connection is None:
            return tool_result

        name = ds_state.spec.name

        if not ds_state.connection.last_call_was_connection_error:
            # Success — reset counter
            if ds_state.consecutive_failures > 0:
                logger.info(
                    "Downstream '%s' recovered after %d failure(s)",
                    name,
                    ds_state.consecutive_failures,
                )
            ds_state.consecutive_failures = 0

            # Probe success: HALF_OPEN → CLOSED
            if is_probe and ds_state.circuit_state == CircuitState.HALF_OPEN:
                ds_state.circuit_state = CircuitState.CLOSED
                ds_state.circuit_opened_at = None
                logger.info(
                    "Circuit breaker recovered for %s",
                    name,
                )

            return tool_result

        # Connection error detected
        ds_state.consecutive_failures += 1
        logger.warning(
            "Downstream '%s' connection error (%d/%d): %s",
            name,
            ds_state.consecutive_failures,
            _CIRCUIT_BREAKER_THRESHOLD,
            _extract_result_text(tool_result) or "unknown",
        )

        # Probe failure: HALF_OPEN → OPEN (restart cooldown)
        if is_probe and ds_state.circuit_state == CircuitState.HALF_OPEN:
            ds_state.circuit_state = CircuitState.OPEN
            ds_state.circuit_opened_at = datetime.now(timezone.utc)
            logger.warning(
                "Circuit breaker probe failed for %s, reopening",
                name,
            )
            return tool_result

        if ds_state.consecutive_failures >= _CIRCUIT_BREAKER_THRESHOLD:
            if ds_state.circuit_state == CircuitState.CLOSED:
                ds_state.circuit_state = CircuitState.OPEN
                ds_state.circuit_opened_at = datetime.now(timezone.utc)
                logger.error(
                    "Downstream '%s' marked UNHEALTHY after %d consecutive "
                    "failures — circuit breaker open",
                    name,
                    ds_state.consecutive_failures,
                )
            return tool_result

        # Attempt ONE restart on first/second failure
        restarted = await self._attempt_restart(ds_state)
        if restarted:
            ds_state.consecutive_failures = 0
            logger.info(
                "Downstream '%s' restarted successfully, tools re-discovered",
                name,
            )
        return tool_result

    async def _attempt_restart(self, ds_state: _DownstreamState) -> bool:
        """Try to reconnect a specific downstream server.

        Returns ``True`` on success, ``False`` on failure.
        """
        if ds_state.connection is None:
            return False
        try:
            await ds_state.connection.reconnect()
            self._rebuild_tool_map_for(ds_state)
            return True
        except Exception as e:
            logger.error(
                "Downstream '%s' restart failed: %s",
                ds_state.spec.name, e,
            )
            return False

    def _rebuild_tool_map(self) -> None:
        """Rebuild tool_map from first downstream (backward compat)."""
        self._rebuild_tool_map_for(self._first_ds)

    def _rebuild_tool_map_for(self, ds_state: _DownstreamState) -> None:
        """Rebuild tool routing for a specific downstream after restart."""
        if ds_state.connection is None:
            return
        name = ds_state.spec.name

        # Remove old entries for this downstream
        old_tools = list(ds_state.tool_map.keys())
        for prefixed in old_tools:
            self._tool_map.pop(prefixed, None)
            self._tool_to_downstream.pop(prefixed, None)
        ds_state.tool_map.clear()

        # Re-add tools from current downstream
        for tool in ds_state.connection.tools:
            prefixed = f"{name}_{tool['name']}"
            ds_state.tool_map[prefixed] = tool["name"]
            self._tool_map[prefixed] = tool["name"]
            self._tool_to_downstream[prefixed] = name

    def _make_unhealthy_result(
        self, prefixed_name: str, ds_state: _DownstreamState,
    ) -> types.CallToolResult:
        """Return an error result when a downstream is unhealthy."""
        state_label = ds_state.circuit_state.value
        msg = (
            f"Downstream '{ds_state.spec.name}' is unhealthy — "
            f"circuit breaker {state_label}. "
            f"Tool '{prefixed_name}' not forwarded."
        )
        logger.warning("Circuit breaker blocked: %s", prefixed_name)
        return types.CallToolResult(
            content=[types.TextContent(type="text", text=msg)],
            isError=True,
        )

    async def _probe_call(
        self,
        prefixed_name: str,
        ds_state: _DownstreamState,
    ) -> types.CallToolResult | None:
        """Run a protocol-level health probe during HALF_OPEN state.

        Uses ``list_tools()`` as a lightweight health check instead of
        forwarding the user's real request.

        Returns ``None`` on success (caller should proceed with normal
        forwarding) or an error ``CallToolResult`` on failure.
        """
        try:
            await ds_state.connection.list_tools()
        except Exception as e:
            # Probe failed: reopen circuit
            ds_state.circuit_state = CircuitState.OPEN
            ds_state.circuit_opened_at = datetime.now(timezone.utc)
            logger.warning(
                "Circuit breaker probe failed for '%s': %s",
                ds_state.spec.name, e,
            )
            return self._make_unhealthy_result(prefixed_name, ds_state)

        # Probe succeeded: close circuit
        ds_state.circuit_state = CircuitState.CLOSED
        ds_state.circuit_opened_at = None
        ds_state.consecutive_failures = 0
        logger.info(
            "Circuit breaker recovered for '%s' (probe: list_tools)",
            ds_state.spec.name,
        )
        return None

    # -- receipt persistence (Block F) ---------------------------------------

    def _persist_receipt(self, receipt: dict) -> None:
        """Write receipt JSON to the receipt store directory.

        Filename: ``{timestamp}_{receipt_id}.json`` where timestamp
        uses underscores instead of colons for filesystem safety.

        When PII redaction is enabled, **only** the redacted copy is
        persisted to disk (as ``*.redacted.json``).  The unredacted
        receipt exists only in memory during the request -- the
        signature covers the original content, but the stored file
        replaces sensitive fields with hash placeholders.

        When redaction is disabled, the original receipt is persisted
        as ``*.json`` with no modifications.
        """
        if not self._receipt_store_path:
            return

        from sanna.utils.safe_io import atomic_write_sync, ensure_secure_dir

        store_dir = Path(self._receipt_store_path)
        ensure_secure_dir(store_dir)

        ts = receipt.get("timestamp", "")
        # Sanitize for filesystem: replace colons and + with underscores
        safe_ts = ts.replace(":", "_").replace("+", "_")
        receipt_id = receipt.get("receipt_id", uuid.uuid4().hex[:8])

        # Block G: when redaction enabled, persist with .redacted.json suffix.
        # Since SEC-1, redaction markers are applied BEFORE signing in
        # _generate_receipt(), so the receipt already contains markers and
        # its hashes/fingerprint/signature are consistent with them.
        if self._redaction_config.enabled:
            redacted_filename = f"{safe_ts}_{receipt_id}.redacted.json"
            redacted_path = store_dir / redacted_filename
            try:
                atomic_write_sync(
                    redacted_path,
                    json.dumps(receipt, indent=2),
                    mode=0o600,
                )
                logger.info(
                    "Redacted receipt persisted: %s",
                    redacted_filename,
                )
            except OSError as e:
                logger.error(
                    "Failed to persist redacted receipt %s: %s",
                    redacted_filename, e,
                )
        else:
            # No redaction — persist the original signed receipt
            filename = f"{safe_ts}_{receipt_id}.json"
            filepath = store_dir / filename
            try:
                atomic_write_sync(
                    filepath,
                    json.dumps(receipt, indent=2),
                    mode=0o600,
                )
                logger.info("Receipt persisted: %s", filename)
            except OSError as e:
                logger.error("Failed to persist receipt %s: %s", filename, e)

    async def _persist_receipt_async(self, receipt: dict) -> None:
        """Offload receipt persistence to thread pool to avoid blocking."""
        loop = _asyncio.get_running_loop()
        await loop.run_in_executor(None, self._persist_receipt, receipt)

    async def _deliver_token_async(
        self, entry: PendingEscalation, token: str,
    ) -> None:
        """Deliver token via configured mechanisms, offloading I/O."""
        loop = _asyncio.get_running_loop()
        await loop.run_in_executor(None, self._deliver_token, entry, token)

    # -- call forwarding with enforcement ------------------------------------

    async def _forward_call(
        self,
        name: str,
        arguments: dict[str, Any] | None,
    ) -> types.CallToolResult:
        """Evaluate policy, enforce, forward if allowed, generate receipt."""
        # Block E: handle meta-tools
        if name == _META_TOOL_APPROVE:
            return await self._handle_approve(arguments or {})
        if name == _META_TOOL_DENY:
            return await self._handle_deny(arguments or {})

        # Route to correct downstream
        lookup = self._get_ds_for_tool(name)
        if lookup is None:
            return types.CallToolResult(
                content=[types.TextContent(
                    type="text", text=f"Unknown tool: {name}",
                )],
                isError=True,
            )
        ds_state, original = lookup

        if ds_state.connection is None:
            return types.CallToolResult(
                content=[types.TextContent(
                    type="text",
                    text=(
                        f"Gateway not connected to downstream server "
                        f"'{ds_state.spec.name}'"
                    ),
                )],
                isError=True,
            )

        arguments = arguments or {}

        # Block G: warn on "justification" without "_justification"
        if "justification" in arguments and "_justification" not in arguments:
            logger.warning(
                "Tool call to '%s' includes 'justification' but not "
                "'_justification'. Sanna requires '_justification' "
                "(with leading underscore). The 'justification' field "
                "will be ignored for governance evaluation.",
                name,
            )

        # Block F: circuit breaker — per-downstream state check
        if ds_state.circuit_state == CircuitState.OPEN:
            # Check if cooldown has elapsed → transition to HALF_OPEN
            if ds_state.circuit_opened_at is not None:
                elapsed = (
                    datetime.now(timezone.utc) - ds_state.circuit_opened_at
                ).total_seconds()
                if elapsed >= ds_state.spec.circuit_breaker_cooldown:
                    # Transition to HALF_OPEN — probe with list_tools
                    ds_state.circuit_state = CircuitState.HALF_OPEN
                    logger.info(
                        "Circuit breaker cooldown elapsed for '%s' "
                        "(%.1fs) — probing with list_tools",
                        ds_state.spec.name,
                        elapsed,
                    )
                    probe_result = await self._probe_call(
                        name, ds_state,
                    )
                    if probe_result is not None:
                        # Probe failed — return error with receipt
                        if self._constitution is not None:
                            receipt = self._generate_error_receipt(
                                prefixed_name=name,
                                original_name=original,
                                arguments=arguments,
                                error_text=_extract_result_text(
                                    probe_result,
                                ),
                                server_name=ds_state.spec.name,
                                boundary_type="downstream_unhealthy",
                            )
                            self._last_receipt = receipt
                            await self._persist_receipt_async(receipt)
                        return probe_result
                    # Probe succeeded — circuit now CLOSED, fall through

            # Still OPEN (cooldown not elapsed or probe didn't run) — block
            if ds_state.circuit_state == CircuitState.OPEN:
                error_result = self._make_unhealthy_result(name, ds_state)
                if self._constitution is not None:
                    receipt = self._generate_error_receipt(
                        prefixed_name=name,
                        original_name=original,
                        arguments=arguments,
                        error_text=_extract_result_text(error_result),
                        server_name=ds_state.spec.name,
                        boundary_type="downstream_unhealthy",
                    )
                    self._last_receipt = receipt
                    await self._persist_receipt_async(receipt)
                return error_result

        if ds_state.circuit_state == CircuitState.HALF_OPEN:
            # Already probing — block concurrent calls
            error_result = self._make_unhealthy_result(name, ds_state)
            if self._constitution is not None:
                receipt = self._generate_error_receipt(
                    prefixed_name=name,
                    original_name=original,
                    arguments=arguments,
                    error_text=_extract_result_text(error_result),
                    server_name=ds_state.spec.name,
                    boundary_type="downstream_unhealthy",
                )
                self._last_receipt = receipt
                await self._persist_receipt_async(receipt)
            return error_result

        # CLOSED — forward normally
        # No constitution -> transparent passthrough (Block B behavior)
        if self._constitution is None:
            result = await ds_state.connection.call_tool(
                original, arguments,
            )
            await self._after_downstream_call(result, ds_state)
            return result

        # -- Block C: enforcement --
        return await self._enforced_call(
            name, original, arguments, ds_state,
        )

    async def _enforced_call(
        self,
        prefixed_name: str,
        original_name: str,
        arguments: dict[str, Any],
        ds_state: _DownstreamState,
        is_probe: bool = False,
    ) -> types.CallToolResult:
        """Run enforcement pipeline: evaluate, enforce, receipt."""
        from sanna.enforcement import evaluate_authority, AuthorityDecision
        from sanna.receipt import HaltEvent
        from sanna.middleware import (
            generate_constitution_receipt,
            build_trace_data,
        )

        server_name = ds_state.spec.name

        # 1. Resolve policy for this downstream
        policy_override = self._resolve_policy(original_name, ds_state)
        if policy_override is not None:
            if policy_override == "cannot_execute":
                decision = AuthorityDecision(
                    decision="halt",
                    reason=f"Policy override: {original_name} is cannot_execute",
                    boundary_type="cannot_execute",
                )
            elif policy_override == "must_escalate":
                decision = AuthorityDecision(
                    decision="escalate",
                    reason=(
                        f"Policy override: {original_name} "
                        f"requires escalation"
                    ),
                    boundary_type="must_escalate",
                )
            else:
                decision = AuthorityDecision(
                    decision="allow",
                    reason=f"Policy override: {original_name} is can_execute",
                    boundary_type="can_execute",
                )
        else:
            decision = evaluate_authority(
                original_name, arguments, self._constitution,
            )

        # 2. Build authority_decisions record
        authority_decisions = [{
            "action": original_name,
            "decision": decision.decision,
            "reason": decision.reason,
            "boundary_type": decision.boundary_type,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }]

        # 3. Block G: Run reasoning evaluation if configured
        reasoning_evaluation = None
        if self._reasoning_evaluator:
            reasoning_config = self._constitution.reasoning

            # evaluate_before_escalation gating: skip eval when false
            # and decision is escalate — eval deferred to _handle_approve()
            skip_reasoning = (
                reasoning_config
                and not reasoning_config.evaluate_before_escalation
                and decision.decision == "escalate"
            )

            if not skip_reasoning:
                try:
                    reasoning_evaluation = (
                        await self._reasoning_evaluator.evaluate(
                            tool_name=original_name,
                            args=arguments,
                            enforcement_level=decision.boundary_type,
                        )
                    )
                except Exception:
                    logger.exception(
                        "Reasoning evaluator error for %s", original_name,
                    )
                    from sanna.gateway.receipt_v2 import ReasoningEvaluation
                    reasoning_evaluation = ReasoningEvaluation(
                        assurance="none",
                        checks=[],
                        overall_score=0.0,
                        passed=False,
                        failure_reason="evaluator_error",
                    )

            # Handle reasoning failure according to constitution config
            if reasoning_evaluation and not reasoning_evaluation.passed:
                if reasoning_config:
                    fr = reasoning_evaluation.failure_reason

                    # A. on_missing_justification enforcement
                    if fr == "missing_required_justification":
                        action = reasoning_config.on_missing_justification
                        if action == "block":
                            decision = AuthorityDecision(
                                decision="halt",
                                reason=(
                                    "Missing required justification for "
                                    f"{original_name}"
                                ),
                                boundary_type=decision.boundary_type,
                            )
                            authority_decisions.append({
                                "action": original_name,
                                "decision": "halt",
                                "reason": decision.reason,
                                "boundary_type": decision.boundary_type,
                                "timestamp": datetime.now(
                                    timezone.utc,
                                ).isoformat(),
                            })
                        elif action == "escalate":
                            decision = AuthorityDecision(
                                decision="escalate",
                                reason=(
                                    "Missing justification, escalating: "
                                    f"{original_name}"
                                ),
                                boundary_type="must_escalate",
                            )
                            authority_decisions.append({
                                "action": original_name,
                                "decision": "escalate",
                                "reason": decision.reason,
                                "boundary_type": "must_escalate",
                                "timestamp": datetime.now(
                                    timezone.utc,
                                ).isoformat(),
                            })
                        # action == "allow" → no override, pass through

                    # B. auto_deny_on_reasoning_failure (takes priority)
                    elif reasoning_config.auto_deny_on_reasoning_failure:
                        decision = AuthorityDecision(
                            decision="halt",
                            reason=(
                                "Reasoning evaluation failed: "
                                f"{fr}"
                            ),
                            boundary_type=decision.boundary_type,
                        )
                        authority_decisions.append({
                            "action": original_name,
                            "decision": "halt",
                            "reason": decision.reason,
                            "boundary_type": decision.boundary_type,
                            "timestamp": datetime.now(
                                timezone.utc,
                            ).isoformat(),
                        })

                    # C. on_check_error enforcement
                    elif reasoning_config.on_check_error == "block":
                        decision = AuthorityDecision(
                            decision="halt",
                            reason=(
                                "Reasoning check failed: "
                                f"{fr}"
                            ),
                            boundary_type=decision.boundary_type,
                        )
                        authority_decisions.append({
                            "action": original_name,
                            "decision": "halt",
                            "reason": decision.reason,
                            "boundary_type": decision.boundary_type,
                            "timestamp": datetime.now(
                                timezone.utc,
                            ).isoformat(),
                        })
                    elif (
                        reasoning_config.on_check_error == "escalate"
                        and decision.decision == "allow"
                    ):
                        decision = AuthorityDecision(
                            decision="escalate",
                            reason=(
                                "Reasoning evaluation failed, "
                                "escalating: "
                                f"{fr}"
                            ),
                            boundary_type="must_escalate",
                        )
                        authority_decisions.append({
                            "action": original_name,
                            "decision": "escalate",
                            "reason": decision.reason,
                            "boundary_type": "must_escalate",
                            "timestamp": datetime.now(
                                timezone.utc,
                            ).isoformat(),
                        })
                    # on_check_error == "allow" → no override

        # 4. Enforce and get result
        result_text = ""
        tool_result = None
        enforcement_obj = None

        if decision.decision == "halt":
            result_text = f"Action denied by policy: {decision.reason}"
            enforcement_obj = HaltEvent(
                halted=True,
                reason=decision.reason,
                failed_checks=[],
                timestamp=datetime.now(timezone.utc).isoformat(),
                enforcement_mode="halt",
            )
            logger.warning(
                "DENY %s: %s", original_name, decision.reason,
            )
        elif decision.decision == "escalate":
            logger.info(
                "ESCALATE %s: %s", original_name, decision.reason,
            )
            # Block E: create pending escalation instead of denying
            return await self._handle_escalation(
                prefixed_name, original_name, arguments,
                decision, ds_state,
                reasoning_evaluation=reasoning_evaluation,
            )
        else:
            logger.info("ALLOW %s", original_name)
            # Strip _justification before forwarding to downstream
            forward_args = {
                k: v for k, v in arguments.items()
                if k != "_justification"
            }
            tool_result = await ds_state.connection.call_tool(
                original_name, forward_args,
            )
            # Block F: crash recovery
            await self._after_downstream_call(
                tool_result, ds_state, is_probe=is_probe,
            )
            result_text = _extract_result_text(tool_result)

        # 5. Generate receipt
        downstream_is_error = (
            tool_result is not None and tool_result.isError is True
        )
        receipt = self._generate_receipt(
            prefixed_name=prefixed_name,
            original_name=original_name,
            arguments=arguments,
            result_text=result_text,
            decision=decision,
            authority_decisions=authority_decisions,
            enforcement=enforcement_obj,
            server_name=server_name,
            downstream_is_error=downstream_is_error,
            reasoning_evaluation=reasoning_evaluation,
        )

        self._last_receipt = receipt
        await self._persist_receipt_async(receipt)

        # 6. Return result
        if decision.decision == "halt":
            return types.CallToolResult(
                content=[types.TextContent(
                    type="text", text=result_text,
                )],
                isError=True,
            )
        else:
            return tool_result

    # -- escalation handling (Block E) ---------------------------------------

    async def _handle_escalation(
        self,
        prefixed_name: str,
        original_name: str,
        arguments: dict[str, Any],
        decision: Any,
        ds_state: _DownstreamState,
        reasoning_evaluation: Any = None,
    ) -> types.CallToolResult:
        """Create a pending escalation and return structured result."""
        server_name = ds_state.spec.name

        # 1. Store pending escalation
        try:
            entry = await self._escalation_store.create_async(
                prefixed_name=prefixed_name,
                original_name=original_name,
                arguments=arguments,
                server_name=server_name,
                reason=decision.reason,
            )
        except RuntimeError as exc:
            logger.warning("Escalation store full: %s", exc)
            return types.CallToolResult(
                content=[types.TextContent(
                    type="text",
                    text=json.dumps({
                        "error": "ESCALATION_STORE_FULL",
                        "detail": str(exc),
                    }),
                )],
                isError=True,
            )

        # 2. Compute and emit approval token (out-of-band via stderr)
        if self._require_approval_token:
            token = self._compute_approval_token(entry)
            entry.token_hash = self._hash_token(token)
            await self._deliver_token_async(entry, token)
            instruction = (
                "Approval token required. The user must provide "
                "the approval token displayed in the gateway terminal."
            )
        else:
            instruction = (
                "This action requires user approval. Please present "
                "the details of what you want to do and ask the user "
                "to confirm before proceeding."
            )

        # 3. Generate escalation receipt
        escalation_result = {
            "status": "ESCALATION_REQUIRED",
            "escalation_id": entry.escalation_id,
            "tool": prefixed_name,
            "parameters": arguments,
            "reason": decision.reason,
            "constitution_rule": (
                f"authority_boundaries.{decision.boundary_type}"
            ),
            "instruction": instruction,
        }
        result_text = json.dumps(escalation_result, sort_keys=True)

        authority_decisions = [{
            "action": original_name,
            "decision": decision.decision,
            "reason": decision.reason,
            "boundary_type": decision.boundary_type,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }]

        receipt = self._generate_receipt(
            prefixed_name=prefixed_name,
            original_name=original_name,
            arguments=arguments,
            result_text=result_text,
            decision=decision,
            authority_decisions=authority_decisions,
            escalation_id=entry.escalation_id,
            server_name=server_name,
            reasoning_evaluation=reasoning_evaluation,
        )

        entry.escalation_receipt_id = receipt["receipt_id"]
        self._last_receipt = receipt
        await self._persist_receipt_async(receipt)

        # 4. Return structured escalation result
        return types.CallToolResult(
            content=[types.TextContent(
                type="text", text=result_text,
            )],
        )

    async def _handle_approve(
        self, arguments: dict[str, Any],
    ) -> types.CallToolResult:
        """Handle sanna_approve_escalation meta-tool call."""
        # FIX-38: Strict argument type validation
        escalation_id = arguments.get("escalation_id")
        approval_token = arguments.get("approval_token")

        if not isinstance(escalation_id, str):
            return types.CallToolResult(
                content=[types.TextContent(
                    type="text",
                    text=json.dumps({"error": "escalation_id must be a string"}),
                )],
                isError=True,
            )
        if approval_token is not None and not isinstance(approval_token, str):
            return types.CallToolResult(
                content=[types.TextContent(
                    type="text",
                    text=json.dumps({"error": "approval_token must be a string"}),
                )],
                isError=True,
            )
        if not escalation_id.startswith("esc_"):
            return types.CallToolResult(
                content=[types.TextContent(
                    type="text",
                    text=json.dumps({"error": "invalid escalation_id format"}),
                )],
                isError=True,
            )

        if approval_token is None:
            approval_token = ""
        override_reason = arguments.get("override_reason", "")
        override_detail = arguments.get("override_detail", "")
        if not escalation_id:
            return types.CallToolResult(
                content=[types.TextContent(
                    type="text",
                    text=json.dumps({
                        "error": "MISSING_PARAMETER",
                        "detail": "escalation_id is required",
                    }),
                )],
                isError=True,
            )

        entry = self._escalation_store.get(escalation_id)
        if entry is None:
            return types.CallToolResult(
                content=[types.TextContent(
                    type="text",
                    text=json.dumps({
                        "error": "ESCALATION_NOT_FOUND",
                        "escalation_id": escalation_id,
                    }),
                )],
                isError=True,
            )

        if self._escalation_store.is_expired(entry):
            await self._escalation_store.remove_async(escalation_id)
            return types.CallToolResult(
                content=[types.TextContent(
                    type="text",
                    text=json.dumps({
                        "error": "ESCALATION_EXPIRED",
                        "escalation_id": escalation_id,
                    }),
                )],
                isError=True,
            )

        # Guard: only pending escalations can be approved
        if entry.status == "approved":
            logger.warning(
                "Duplicate approve for %s (status: approved)",
                escalation_id,
            )
            return types.CallToolResult(
                content=[types.TextContent(
                    type="text",
                    text=json.dumps({
                        "error": "ESCALATION_ALREADY_EXECUTING",
                        "escalation_id": escalation_id,
                        "detail": (
                            "This escalation is already being executed. "
                            "It may have been approved previously."
                        ),
                    }),
                )],
                isError=True,
            )
        if entry.status == "failed":
            logger.warning(
                "Approve attempted for failed escalation %s",
                escalation_id,
            )
            return types.CallToolResult(
                content=[types.TextContent(
                    type="text",
                    text=json.dumps({
                        "error": "ESCALATION_FAILED",
                        "escalation_id": escalation_id,
                        "detail": (
                            "This escalation previously failed during "
                            "execution. Create a new escalation to retry."
                        ),
                    }),
                )],
                isError=True,
            )

        # Validate approval token (after existence/expiry/status checks)
        if self._require_approval_token:
            if not approval_token:
                return types.CallToolResult(
                    content=[types.TextContent(
                        type="text",
                        text=json.dumps({
                            "error": "MISSING_APPROVAL_TOKEN",
                            "escalation_id": escalation_id,
                            "detail": (
                                "approval_token is required. Use the "
                                "token displayed in the gateway terminal."
                            ),
                        }),
                    )],
                    isError=True,
                )
            # SEC-5: Re-derive the expected token from the HMAC secret
            # and stored escalation attributes — never trust stored
            # token_hash from the persisted file for approval decisions.
            expected_token = self._compute_approval_token(entry)
            if not hmac.compare_digest(approval_token, expected_token):
                return types.CallToolResult(
                    content=[types.TextContent(
                        type="text",
                        text=json.dumps({
                            "error": "INVALID_APPROVAL_TOKEN",
                            "escalation_id": escalation_id,
                            "detail": (
                                "The provided approval token is invalid. "
                                "Use the token displayed in the gateway "
                                "terminal."
                            ),
                        }),
                    )],
                    isError=True,
                )
            approval_method = "token_verified"
            token_hash_for_receipt = entry.token_hash
        else:
            logger.warning(
                "Approval accepted without token verification — "
                "development mode only",
            )
            approval_method = "unverified"
            token_hash_for_receipt = None

        # Validate override_reason when constitution requires it
        if self._approval_requires_reason and not override_reason:
            return types.CallToolResult(
                content=[types.TextContent(
                    type="text",
                    text=json.dumps({
                        "error": "MISSING_OVERRIDE_REASON",
                        "escalation_id": escalation_id,
                        "detail": (
                            "override_reason is required by the "
                            "constitution for escalation approvals."
                        ),
                    }),
                )],
                isError=True,
            )

        # Store override reason/detail on entry for receipt
        entry.override_reason = override_reason
        entry.override_detail = override_detail

        # Mark as approved (keep in store until execution completes)
        await self._escalation_store.mark_status_async(escalation_id, "approved")

        # Block G deferred: reasoning evaluation for evaluate_before_escalation: false
        reasoning_evaluation = None
        if self._reasoning_evaluator:
            reasoning_config = self._constitution.reasoning
            if reasoning_config and not reasoning_config.evaluate_before_escalation:
                try:
                    reasoning_evaluation = (
                        await self._reasoning_evaluator.evaluate(
                            tool_name=entry.original_name,
                            args=entry.arguments,
                            enforcement_level="must_escalate",
                        )
                    )
                except Exception:
                    logger.exception(
                        "Reasoning evaluator error for %s (deferred)",
                        entry.original_name,
                    )
                    from sanna.gateway.receipt_v2 import ReasoningEvaluation
                    reasoning_evaluation = ReasoningEvaluation(
                        assurance="none",
                        checks=[],
                        overall_score=0.0,
                        passed=False,
                        failure_reason="evaluator_error",
                    )

                # If deferred reasoning fails, deny even after approval
                if reasoning_evaluation and not reasoning_evaluation.passed:
                    deny = False
                    fr = reasoning_evaluation.failure_reason

                    if fr == "missing_required_justification":
                        if reasoning_config.on_missing_justification == "block":
                            deny = True
                    elif reasoning_config.auto_deny_on_reasoning_failure:
                        deny = True
                    elif reasoning_config.on_check_error == "block":
                        deny = True

                    if deny:
                        await self._escalation_store.mark_status_async(
                            escalation_id, "failed",
                        )
                        from sanna.enforcement import AuthorityDecision as AD
                        from sanna.receipt import HaltEvent

                        deny_reason = (
                            f"Reasoning evaluation failed after approval: "
                            f"{fr}"
                        )
                        deny_decision = AD(
                            decision="halt",
                            reason=deny_reason,
                            boundary_type="must_escalate",
                        )
                        receipt = self._generate_receipt(
                            prefixed_name=entry.prefixed_name,
                            original_name=entry.original_name,
                            arguments=entry.arguments,
                            result_text=deny_reason,
                            decision=deny_decision,
                            authority_decisions=[{
                                "action": entry.original_name,
                                "decision": "halt",
                                "reason": deny_reason,
                                "boundary_type": "must_escalate",
                                "timestamp": datetime.now(
                                    timezone.utc,
                                ).isoformat(),
                            }],
                            escalation_id=escalation_id,
                            escalation_receipt_id=entry.escalation_receipt_id,
                            escalation_resolution="denied_by_reasoning",
                            server_name=entry.server_name,
                            reasoning_evaluation=reasoning_evaluation,
                        )
                        self._last_receipt = receipt
                        await self._persist_receipt_async(receipt)

                        return types.CallToolResult(
                            content=[types.TextContent(
                                type="text",
                                text=deny_reason,
                            )],
                            isError=True,
                        )

        # Look up correct downstream for this escalation
        ds_state = self._downstream_states.get(entry.server_name)
        if ds_state is None or ds_state.connection is None:
            await self._escalation_store.mark_status_async(escalation_id, "failed")
            return types.CallToolResult(
                content=[types.TextContent(
                    type="text",
                    text=(
                        f"Gateway not connected to downstream server "
                        f"'{entry.server_name}'"
                    ),
                )],
                isError=True,
            )

        try:
            # Strip _justification before forwarding to downstream
            forward_args = {
                k: v for k, v in entry.arguments.items()
                if k != "_justification"
            }
            tool_result = await ds_state.connection.call_tool(
                entry.original_name, forward_args,
            )
        except Exception:
            await self._escalation_store.mark_status_async(escalation_id, "failed")
            raise
        # Block F: crash recovery
        await self._after_downstream_call(tool_result, ds_state)

        # Execution succeeded — remove from store
        await self._escalation_store.remove_async(escalation_id)

        result_text = _extract_result_text(tool_result)

        # Generate approval receipt with chain to escalation receipt
        from sanna.enforcement import AuthorityDecision

        decision = AuthorityDecision(
            decision="allow",
            reason=(
                f"User approved escalation {escalation_id} for "
                f"{entry.original_name}"
            ),
            boundary_type="must_escalate",
        )
        authority_decisions = [{
            "action": entry.original_name,
            "decision": "allow",
            "reason": decision.reason,
            "boundary_type": "must_escalate",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }]

        receipt = self._generate_receipt(
            prefixed_name=entry.prefixed_name,
            original_name=entry.original_name,
            arguments=entry.arguments,
            result_text=result_text,
            decision=decision,
            authority_decisions=authority_decisions,
            escalation_id=escalation_id,
            escalation_receipt_id=entry.escalation_receipt_id,
            escalation_resolution="approved",
            approval_method=approval_method,
            token_hash=token_hash_for_receipt,
            override_reason=entry.override_reason or None,
            override_detail=entry.override_detail or None,
            server_name=entry.server_name,
            reasoning_evaluation=reasoning_evaluation,
            downstream_is_error=tool_result.isError is True,
        )

        self._last_receipt = receipt
        await self._persist_receipt_async(receipt)

        return tool_result

    async def _handle_deny(
        self, arguments: dict[str, Any],
    ) -> types.CallToolResult:
        """Handle sanna_deny_escalation meta-tool call."""
        # FIX-38: Strict argument type validation
        escalation_id = arguments.get("escalation_id")

        if not isinstance(escalation_id, str):
            return types.CallToolResult(
                content=[types.TextContent(
                    type="text",
                    text=json.dumps({"error": "escalation_id must be a string"}),
                )],
                isError=True,
            )
        if not escalation_id.startswith("esc_"):
            return types.CallToolResult(
                content=[types.TextContent(
                    type="text",
                    text=json.dumps({"error": "invalid escalation_id format"}),
                )],
                isError=True,
            )

        if not escalation_id:
            return types.CallToolResult(
                content=[types.TextContent(
                    type="text",
                    text=json.dumps({
                        "error": "MISSING_PARAMETER",
                        "detail": "escalation_id is required",
                    }),
                )],
                isError=True,
            )

        entry = self._escalation_store.get(escalation_id)
        if entry is None:
            return types.CallToolResult(
                content=[types.TextContent(
                    type="text",
                    text=json.dumps({
                        "error": "ESCALATION_NOT_FOUND",
                        "escalation_id": escalation_id,
                    }),
                )],
                isError=True,
            )

        if self._escalation_store.is_expired(entry):
            await self._escalation_store.remove_async(escalation_id)
            return types.CallToolResult(
                content=[types.TextContent(
                    type="text",
                    text=json.dumps({
                        "error": "ESCALATION_EXPIRED",
                        "escalation_id": escalation_id,
                    }),
                )],
                isError=True,
            )

        # Remove from store (resolved)
        await self._escalation_store.remove_async(escalation_id)

        result_text = (
            f"Escalation {escalation_id} denied by user. "
            f"Action {entry.original_name} was not executed."
        )

        # Generate denial receipt with chain to escalation receipt
        from sanna.enforcement import AuthorityDecision

        decision = AuthorityDecision(
            decision="halt",
            reason=f"User denied escalation {escalation_id}",
            boundary_type="must_escalate",
        )
        authority_decisions = [{
            "action": entry.original_name,
            "decision": "halt",
            "reason": decision.reason,
            "boundary_type": "must_escalate",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }]

        from sanna.receipt import HaltEvent

        enforcement_obj = HaltEvent(
            halted=True,
            reason=f"User denied escalation {escalation_id}",
            failed_checks=[],
            timestamp=datetime.now(timezone.utc).isoformat(),
            enforcement_mode="halt",
        )

        receipt = self._generate_receipt(
            prefixed_name=entry.prefixed_name,
            original_name=entry.original_name,
            arguments=entry.arguments,
            result_text=result_text,
            decision=decision,
            authority_decisions=authority_decisions,
            enforcement=enforcement_obj,
            escalation_id=escalation_id,
            escalation_receipt_id=entry.escalation_receipt_id,
            escalation_resolution="denied",
            server_name=entry.server_name,
        )

        self._last_receipt = receipt
        await self._persist_receipt_async(receipt)

        return types.CallToolResult(
            content=[types.TextContent(
                type="text",
                text=json.dumps({
                    "status": "denied",
                    "escalation_id": escalation_id,
                    "action": entry.original_name,
                }),
            )],
        )

    # -- error receipt generation (Block F) -----------------------------------

    def _generate_error_receipt(
        self,
        *,
        prefixed_name: str,
        original_name: str,
        arguments: dict[str, Any],
        error_text: str,
        server_name: str | None = None,
        boundary_type: str = "execution_failed",
        reasoning_evaluation: Any = None,
    ) -> dict:
        """Generate an error receipt for downstream failures.

        Used when the circuit breaker blocks a call or an unrecoverable
        error occurs.

        Args:
            boundary_type: The failure classification.  Use
                ``"downstream_unhealthy"`` for connection/circuit-breaker
                failures and ``"execution_failed"`` for downstream
                runtime errors.  Policy blocks use ``"cannot_execute"``
                (set elsewhere, not here).
            reasoning_evaluation: Optional reasoning evaluation result
                to preserve in the error receipt for audit purposes.
        """
        from sanna.enforcement import AuthorityDecision
        from sanna.receipt import HaltEvent

        decision = AuthorityDecision(
            decision="halt",
            reason=f"Downstream error: {error_text}",
            boundary_type=boundary_type,
        )
        authority_decisions = [{
            "action": original_name,
            "decision": "halt",
            "reason": decision.reason,
            "boundary_type": boundary_type,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }]
        enforcement_obj = HaltEvent(
            halted=True,
            reason=error_text,
            failed_checks=[],
            timestamp=datetime.now(timezone.utc).isoformat(),
            enforcement_mode="halt",
        )

        return self._generate_receipt(
            prefixed_name=prefixed_name,
            original_name=original_name,
            arguments=arguments,
            result_text=error_text,
            decision=decision,
            authority_decisions=authority_decisions,
            enforcement=enforcement_obj,
            server_name=server_name,
            reasoning_evaluation=reasoning_evaluation,
        )

    # -- receipt generation --------------------------------------------------

    def _generate_receipt(
        self,
        *,
        prefixed_name: str,
        original_name: str,
        arguments: dict[str, Any],
        result_text: str,
        decision: Any,
        authority_decisions: list,
        enforcement: Any = None,
        escalation_id: str | None = None,
        escalation_receipt_id: str | None = None,
        escalation_resolution: str | None = None,
        approval_method: str | None = None,
        token_hash: str | None = None,
        override_reason: str | None = None,
        override_detail: str | None = None,
        server_name: str | None = None,
        downstream_is_error: bool = False,
        reasoning_evaluation: Any = None,
    ) -> dict:
        """Generate and optionally sign a gateway receipt.

        v2.0: Computes a Receipt Triad (input_hash, reasoning_hash,
        action_hash) and embeds it in ``extensions["com.sanna.gateway"]``.  The
        triad binds the tool call to any agent justification for
        auditability.  The ``_justification`` key in arguments is
        extracted and hashed separately, then stripped from the
        forwarded arguments.
        """
        from sanna.middleware import (
            generate_constitution_receipt,
            build_trace_data,
        )
        from sanna.hashing import hash_text, hash_obj
        from sanna.gateway.receipt_v2 import (
            compute_receipt_triad,
            receipt_triad_to_dict,
            truncate_for_storage,
            RECEIPT_VERSION_2,
        )

        # Resolve server_name from tool routing if not explicit
        if server_name is None:
            ds_name = self._tool_to_downstream.get(prefixed_name)
            server_name = ds_name or self._first_ds.spec.name

        correlation_id = f"gw-{uuid.uuid4().hex[:12]}"
        context_str = json.dumps(
            arguments, sort_keys=True,
        ) if arguments else ""

        # Compute fidelity hashes from FULL content before truncation.
        # MCP tool arguments may contain non-integer floats, so use
        # _coerce_floats_for_hashing to ensure deterministic hashing
        # without crashing on arbitrary float values.
        if arguments:
            from sanna.gateway.receipt_v2 import _coerce_floats_for_hashing
            arguments_hash = hash_obj(_coerce_floats_for_hashing(arguments))
        else:
            arguments_hash = hash_text("")
        tool_output_hash = hash_text(result_text) if result_text else hash_text("")

        # Truncate large payloads for storage (hashes computed above)
        stored_context = truncate_for_storage(context_str)
        stored_output = truncate_for_storage(result_text)

        trace_data = build_trace_data(
            correlation_id=correlation_id,
            query=original_name,
            context=stored_context or "",
            output=stored_output or "",
        )

        # v2.0: Extract justification and compute Receipt Triad
        # justification_stripped is True if _justification was present (any type)
        justification_stripped = "_justification" in arguments
        justification = arguments.get("_justification")
        if not isinstance(justification, str):
            justification = None

        triad = compute_receipt_triad(original_name, arguments, justification)

        extensions: dict[str, Any] = {
            "gateway": {
                "server_name": server_name,
                "tool_name": original_name,
                "prefixed_name": prefixed_name,
                "decision": decision.decision,
                "boundary_type": decision.boundary_type,
                "arguments_hash": arguments_hash,
                "arguments_hash_method": "sanna_canonical",
                "tool_output_hash": tool_output_hash,
                "downstream_is_error": downstream_is_error,
            },
            # v2.0: Receipt Triad and structured records
            # NOTE: action.args stores only the arguments_hash (not raw
            # args) because raw args may be large.  Raw args are
            # recoverable from the receipt's inputs.context field.
            "com.sanna.gateway": {
                "receipt_version": RECEIPT_VERSION_2,
                "receipt_triad": receipt_triad_to_dict(triad),
                "action": {
                    "tool": original_name,
                    "args_hash": arguments_hash,
                    "justification_stripped": justification_stripped,
                },
                "enforcement": {
                    "level": decision.boundary_type,
                    "constitution_version": (
                        self._constitution.schema_version
                        if self._constitution else ""
                    ),
                    "constitution_hash": (
                        self._constitution.policy_hash
                        if self._constitution
                        and self._constitution.policy_hash
                        else ""
                    ),
                },
            },
        }

        # Block G: embed reasoning evaluation in com.sanna.gateway
        # Use for_signing=True to convert floats to integer basis points
        # for Sanna Canonical JSON compatibility (extensions are hashed).
        if reasoning_evaluation is not None:
            from sanna.gateway.receipt_v2 import (
                reasoning_evaluation_to_dict,
            )

            extensions["com.sanna.gateway"]["reasoning_evaluation"] = (
                reasoning_evaluation_to_dict(
                    reasoning_evaluation, for_signing=True,
                )
            )

        # Include escalation chain info in extensions when present
        if escalation_id is not None:
            extensions["gateway"]["escalation_id"] = escalation_id
        if escalation_receipt_id is not None:
            extensions["gateway"]["escalation_receipt_id"] = (
                escalation_receipt_id
            )
        if escalation_resolution is not None:
            extensions["gateway"]["escalation_resolution"] = (
                escalation_resolution
            )
        if approval_method is not None:
            extensions["gateway"]["approval_method"] = approval_method
        if token_hash is not None:
            extensions["gateway"]["token_hash"] = token_hash
        if override_reason:
            extensions["gateway"]["override_reason"] = override_reason
        if override_detail:
            extensions["gateway"]["override_detail"] = override_detail

        receipt = generate_constitution_receipt(
            trace_data,
            check_configs=self._check_configs or [],
            custom_records=self._custom_records or [],
            constitution_ref=self._constitution_ref,
            constitution_version=(
                self._constitution.schema_version
                if self._constitution else ""
            ),
            extensions=extensions,
            enforcement=enforcement,
            authority_decisions=authority_decisions,
        )

        # SEC-1: Apply redaction markers BEFORE signing so that the
        # signature covers the markers (not the original PII).  The
        # verifier recognises the markers and can confirm content
        # integrity via the embedded original_hash.
        if self._redaction_config.enabled:
            receipt, _redacted = _apply_redaction_markers(
                receipt, self._redaction_config.fields,
            )

        # Sign receipt if key provided
        if self._signing_key_path is not None:
            from sanna.crypto import sign_receipt
            receipt = sign_receipt(receipt, self._signing_key_path)

        return receipt


# ---------------------------------------------------------------------------
# Meta-tools
# ---------------------------------------------------------------------------

def _build_meta_tools() -> list[types.Tool]:
    """Build the gateway's meta-tool definitions."""
    return [
        types.Tool(
            name=_META_TOOL_APPROVE,
            description=(
                "Approve a pending escalation. Requires the HMAC "
                "approval token displayed in the gateway terminal. "
                "Forwards the original tool call to the downstream "
                "server."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "escalation_id": {
                        "type": "string",
                        "description": (
                            "The escalation ID returned by the "
                            "ESCALATION_REQUIRED response."
                        ),
                    },
                    "approval_token": {
                        "type": "string",
                        "description": (
                            "The HMAC approval token displayed in "
                            "the gateway terminal. Required for "
                            "human-bound approval verification."
                        ),
                    },
                    "override_reason": {
                        "type": "string",
                        "description": (
                            "Reason for approving this escalated "
                            "action."
                        ),
                    },
                    "override_detail": {
                        "type": "string",
                        "description": (
                            "Additional context for the approval "
                            "decision."
                        ),
                    },
                },
                "required": ["escalation_id", "approval_token"],
            },
        ),
        types.Tool(
            name=_META_TOOL_DENY,
            description=(
                "Deny a pending escalation. The original tool call "
                "will not be executed."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "escalation_id": {
                        "type": "string",
                        "description": (
                            "The escalation ID returned by the "
                            "ESCALATION_REQUIRED response."
                        ),
                    },
                },
                "required": ["escalation_id"],
            },
        ),
    ]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _dict_to_tool(
    prefixed_name: str, tool_dict: dict[str, Any],
) -> types.Tool:
    """Convert a downstream tool dict into an MCP ``Tool`` object.

    Preserves all schema fields from the downstream tool — only the name
    is replaced with the prefixed gateway name.
    """
    kwargs: dict[str, Any] = {
        "name": prefixed_name,
        "inputSchema": tool_dict["inputSchema"],
    }
    if "description" in tool_dict:
        kwargs["description"] = tool_dict["description"]
    if "outputSchema" in tool_dict:
        kwargs["outputSchema"] = tool_dict["outputSchema"]
    if "title" in tool_dict:
        kwargs["title"] = tool_dict["title"]
    if "annotations" in tool_dict:
        kwargs["annotations"] = types.ToolAnnotations(
            **tool_dict["annotations"],
        )
    return types.Tool(**kwargs)


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def run_gateway() -> None:
    """Parse ``--config`` and run the gateway on stdio.

    Uses :func:`sanna.gateway.config.load_gateway_config` for validated
    config parsing with env var interpolation, path expansion, and
    fail-fast validation.

    Wires ALL downstreams from the config — each gets its own
    ``DownstreamSpec`` with independent policy overrides and
    circuit breaker cooldown.
    """
    import argparse
    import sys

    from sanna.gateway.config import (
        GatewayConfigError,
        build_policy_overrides,
        load_gateway_config,
    )

    parser = argparse.ArgumentParser(
        prog="sanna-gateway",
        description="Sanna MCP enforcement proxy",
    )
    parser.add_argument(
        "--config",
        required=True,
        help="Path to gateway YAML config file",
    )
    parser.add_argument(
        "--no-approval-token",
        action="store_true",
        default=False,
        help=(
            "Disable HMAC approval token verification for "
            "must_escalate approvals. Development/testing only."
        ),
    )
    args = parser.parse_args()

    try:
        config = load_gateway_config(args.config)
    except GatewayConfigError as e:
        print(f"Configuration error: {e}", file=sys.stderr)
        sys.exit(1)

    require_approval_token = not args.no_approval_token
    if not require_approval_token:
        print(
            "[SANNA] WARNING: Approval token verification disabled "
            "(--no-approval-token). Development mode only.",
            file=sys.stderr,
        )

    # Build DownstreamSpec for ALL configured downstreams
    downstream_specs: list[DownstreamSpec] = []
    for ds in config.downstreams:
        policy_overrides = build_policy_overrides(ds)
        downstream_specs.append(DownstreamSpec(
            name=ds.name,
            command=ds.command,
            args=ds.args,
            env=ds.env,
            timeout=ds.timeout,
            policy_overrides=policy_overrides,
            default_policy=ds.default_policy,
            circuit_breaker_cooldown=config.circuit_breaker_cooldown,
            optional=ds.optional,
        ))

    gateway = SannaGateway(
        downstreams=downstream_specs,
        constitution_path=config.constitution_path,
        signing_key_path=config.signing_key_path,
        constitution_public_key_path=(
            config.constitution_public_key_path or None
        ),
        escalation_timeout=config.escalation_timeout,
        max_pending_escalations=config.max_pending_escalations,
        receipt_store_path=config.receipt_store or None,
        require_approval_token=require_approval_token,
        gateway_secret_path=config.gateway_secret_path or None,
        escalation_persist_path=config.escalation_persist_path or None,
        approval_requires_reason=config.approval_requires_reason,
        token_delivery=config.token_delivery,
        require_constitution_sig=config.require_constitution_sig,
        redaction_config=config.redaction,
    )
    # CRIT-01: propagate webhook URL and token expiry to gateway instance
    gateway._approval_webhook_url = config.approval_webhook_url
    gateway._token_expiry_seconds = config.token_expiry_seconds

    import asyncio
    asyncio.run(gateway.run_stdio())
