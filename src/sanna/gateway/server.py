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

import enum
import hashlib
import hmac
import json
import logging
import os
import sys
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


_DEFAULT_MAX_PENDING_ESCALATIONS = 100


class EscalationStore:
    """In-memory store for pending escalations with expiry.

    Not persistent — pending escalations are lost on gateway restart.
    """

    def __init__(
        self,
        timeout: float = _DEFAULT_ESCALATION_TIMEOUT,
        max_pending: int = _DEFAULT_MAX_PENDING_ESCALATIONS,
    ) -> None:
        self._pending: dict[str, PendingEscalation] = {}
        self._timeout = timeout
        self._max_pending = max_pending

    @property
    def timeout(self) -> float:
        return self._timeout

    @property
    def max_pending(self) -> int:
        return self._max_pending

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

        # Enforce capacity limit
        if len(self._pending) >= self._max_pending:
            raise RuntimeError(
                f"Escalation store at capacity "
                f"({self._max_pending} pending). "
                f"Approve or deny existing escalations first."
            )

        esc_id = f"esc_{uuid.uuid4().hex}"
        entry = PendingEscalation(
            escalation_id=esc_id,
            prefixed_name=prefixed_name,
            original_name=original_name,
            arguments=arguments,
            server_name=server_name,
            reason=reason,
            created_at=datetime.now(timezone.utc).isoformat(),
        )
        self._pending[esc_id] = entry
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
        return self._pending.pop(escalation_id, None)

    def mark_status(
        self, escalation_id: str, status: str,
    ) -> PendingEscalation | None:
        """Update the status of a pending escalation in-place."""
        entry = self._pending.get(escalation_id)
        if entry is not None:
            entry.status = status
        return entry

    def __len__(self) -> int:
        return len(self._pending)

    def clear(self) -> None:
        self._pending.clear()


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
    ) -> None:
        # Build downstream specs — either from explicit list or legacy params
        if downstreams is not None:
            if len(downstreams) == 0:
                raise ValueError(
                    "downstreams list must contain at least one entry"
                )
            self._downstream_states: dict[str, _DownstreamState] = {}
            for spec in downstreams:
                if "_" in spec.name:
                    raise ValueError(
                        f"Downstream name '{spec.name}' must not contain "
                        f"underscores (reserved for tool namespace "
                        f"separator). Use hyphens instead: "
                        f"'{spec.name.replace('_', '-')}'"
                    )
                if spec.name in self._downstream_states:
                    raise ValueError(
                        f"Duplicate downstream name: {spec.name}"
                    )
                self._downstream_states[spec.name] = _DownstreamState(
                    spec=spec,
                )
        elif server_name is not None and command is not None:
            # Legacy single-downstream constructor
            if "_" in server_name:
                raise ValueError(
                    f"server_name '{server_name}' must not contain "
                    f"underscores (reserved for tool namespace "
                    f"separator). Use hyphens instead: "
                    f"'{server_name.replace('_', '-')}'"
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
        self._constitution: Any = None
        self._constitution_ref: dict | None = None
        self._check_configs: list | None = None
        self._custom_records: list | None = None
        self._last_receipt: dict | None = None

        # Block G: reasoning evaluator (set in start() after constitution loads)
        self._reasoning_evaluator: Any = None

        # Block E: escalation state
        self._escalation_store = EscalationStore(
            timeout=escalation_timeout,
            max_pending=max_pending_escalations,
        )

        # Approval token: HMAC-bound human verification
        self._require_approval_token = require_approval_token
        self._gateway_secret = os.urandom(32)

        # Block F: hardening state
        self._receipt_store_path = receipt_store_path

        self._setup_handlers()

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

        Token = HMAC-SHA256(gateway_secret,
            escalation_id || tool_name || args_hash || created_at)

        Returns the token as a hex string.
        """
        args_hash = hashlib.sha256(
            json.dumps(entry.arguments, sort_keys=True).encode(),
        ).hexdigest()
        message = (
            f"{entry.escalation_id}|{entry.original_name}|"
            f"{args_hash}|{entry.created_at}"
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
                    logger.warning(
                        "Tool name collision: %s (already registered "
                        "by '%s')",
                        prefixed,
                        self._tool_to_downstream[prefixed],
                    )
                ds_state.tool_map[prefixed] = tool["name"]
                self._tool_map[prefixed] = tool["name"]
                self._tool_to_downstream[prefixed] = spec.name

            logger.info(
                "Downstream '%s' connected: %d tools",
                spec.name,
                len(ds_state.tool_map),
            )

        # Block C: load constitution if configured
        if self._constitution_path is not None:
            from sanna.constitution import (
                load_constitution,
                constitution_to_receipt_ref,
                SannaConstitutionError,
            )
            from sanna.enforcement import configure_checks

            self._constitution = load_constitution(self._constitution_path)
            if not self._constitution.policy_hash:
                raise SannaConstitutionError(
                    f"Constitution is not signed: {self._constitution_path}. "
                    f"Run: sanna-sign-constitution {self._constitution_path}"
                )

            # Verify constitution Ed25519 signature if public key configured
            if self._constitution_public_key_path:
                self._verify_constitution_signature()
            else:
                logger.info(
                    "No constitution public key configured — "
                    "signature verification skipped",
                )

            self._constitution_ref = constitution_to_receipt_ref(
                self._constitution,
            )
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
        """
        if not self._receipt_store_path:
            return

        store_dir = Path(self._receipt_store_path)
        store_dir.mkdir(parents=True, exist_ok=True)
        if sys.platform != "win32":
            os.chmod(store_dir, 0o700)

        ts = receipt.get("timestamp", "")
        # Sanitize for filesystem: replace colons and + with underscores
        safe_ts = ts.replace(":", "_").replace("+", "_")
        receipt_id = receipt.get("receipt_id", uuid.uuid4().hex[:8])
        filename = f"{safe_ts}_{receipt_id}.json"

        filepath = store_dir / filename
        try:
            tmp_path = filepath.with_suffix(".tmp")
            tmp_path.write_text(json.dumps(receipt, indent=2))
            os.replace(str(tmp_path), str(filepath))
            if sys.platform != "win32":
                os.chmod(filepath, 0o600)
            logger.info("Receipt persisted: %s", filename)
        except OSError as e:
            logger.error("Failed to persist receipt %s: %s", filename, e)

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
                            )
                            self._last_receipt = receipt
                            self._persist_receipt(receipt)
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
                    )
                    self._last_receipt = receipt
                    self._persist_receipt(receipt)
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
                )
                self._last_receipt = receipt
                self._persist_receipt(receipt)
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
            reasoning_evaluation = await self._reasoning_evaluator.evaluate(
                tool_name=original_name,
                args=arguments,
                enforcement_level=decision.boundary_type,
            )

            # Handle reasoning failure according to constitution config
            if reasoning_evaluation and not reasoning_evaluation.passed:
                reasoning_config = self._constitution.reasoning
                if reasoning_config:
                    if reasoning_config.auto_deny_on_reasoning_failure:
                        decision = AuthorityDecision(
                            decision="halt",
                            reason=(
                                "Reasoning evaluation failed: "
                                f"{reasoning_evaluation.failure_reason}"
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
                                f"{reasoning_evaluation.failure_reason}"
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

        # 4. Enforce and get result
        result_text = ""
        tool_result = None
        halt_event = None

        if decision.decision == "halt":
            result_text = f"Action denied by policy: {decision.reason}"
            halt_event = HaltEvent(
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
            halt_event=halt_event,
            server_name=server_name,
            downstream_is_error=downstream_is_error,
            reasoning_evaluation=reasoning_evaluation,
        )

        self._last_receipt = receipt
        self._persist_receipt(receipt)

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
            entry = self._escalation_store.create(
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
            print(
                f"[SANNA] Approval token for escalation "
                f"{entry.escalation_id}: {token}",
                file=sys.stderr,
                flush=True,
            )
            print(
                "[SANNA] Provide this token to approve the action.",
                file=sys.stderr,
                flush=True,
            )
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
        self._persist_receipt(receipt)

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
        escalation_id = arguments.get("escalation_id", "")
        approval_token = arguments.get("approval_token", "")
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
            self._escalation_store.remove(escalation_id)
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
            provided_hash = self._hash_token(approval_token)
            if not hmac.compare_digest(provided_hash, entry.token_hash):
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

        # Mark as approved (keep in store until execution completes)
        self._escalation_store.mark_status(escalation_id, "approved")

        # Look up correct downstream for this escalation
        ds_state = self._downstream_states.get(entry.server_name)
        if ds_state is None or ds_state.connection is None:
            self._escalation_store.mark_status(escalation_id, "failed")
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
            self._escalation_store.mark_status(escalation_id, "failed")
            raise
        # Block F: crash recovery
        await self._after_downstream_call(tool_result, ds_state)

        # Execution succeeded — remove from store
        self._escalation_store.remove(escalation_id)

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
            server_name=entry.server_name,
            downstream_is_error=tool_result.isError is True,
        )

        self._last_receipt = receipt
        self._persist_receipt(receipt)

        return tool_result

    async def _handle_deny(
        self, arguments: dict[str, Any],
    ) -> types.CallToolResult:
        """Handle sanna_deny_escalation meta-tool call."""
        escalation_id = arguments.get("escalation_id", "")
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
            self._escalation_store.remove(escalation_id)
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
        self._escalation_store.remove(escalation_id)

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

        halt_event = HaltEvent(
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
            halt_event=halt_event,
            escalation_id=escalation_id,
            escalation_receipt_id=entry.escalation_receipt_id,
            escalation_resolution="denied",
            server_name=entry.server_name,
        )

        self._last_receipt = receipt
        self._persist_receipt(receipt)

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
    ) -> dict:
        """Generate an error receipt for downstream failures.

        Used when the circuit breaker blocks a call or an unrecoverable
        error occurs.
        """
        from sanna.enforcement import AuthorityDecision
        from sanna.receipt import HaltEvent

        decision = AuthorityDecision(
            decision="halt",
            reason=f"Downstream error: {error_text}",
            boundary_type="cannot_execute",
        )
        authority_decisions = [{
            "action": original_name,
            "decision": "halt",
            "reason": decision.reason,
            "boundary_type": "cannot_execute",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }]
        halt_event = HaltEvent(
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
            halt_event=halt_event,
            server_name=server_name,
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
        halt_event: Any = None,
        escalation_id: str | None = None,
        escalation_receipt_id: str | None = None,
        escalation_resolution: str | None = None,
        approval_method: str | None = None,
        token_hash: str | None = None,
        server_name: str | None = None,
        downstream_is_error: bool = False,
        reasoning_evaluation: Any = None,
    ) -> dict:
        """Generate and optionally sign a gateway receipt.

        v2.0: Computes a Receipt Triad (input_hash, reasoning_hash,
        action_hash) and embeds it in ``extensions.gateway_v2``.  The
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
            RECEIPT_VERSION_2,
        )

        # Resolve server_name from tool routing if not explicit
        if server_name is None:
            ds_name = self._tool_to_downstream.get(prefixed_name)
            server_name = ds_name or self._first_ds.spec.name

        trace_id = f"gw-{uuid.uuid4().hex[:12]}"
        context_str = json.dumps(
            arguments, sort_keys=True,
        ) if arguments else ""

        trace_data = build_trace_data(
            trace_id=trace_id,
            query=original_name,
            context=context_str,
            output=result_text,
        )

        # Compute fidelity hashes for auditing
        # hash_obj() uses RFC 8785 canonical JSON which rejects floats.
        # MCP tool arguments commonly contain floats, so fall back to
        # json.dumps for those cases.
        arguments_hash_method = "jcs"
        if arguments:
            try:
                arguments_hash = hash_obj(arguments)
            except TypeError:
                arguments_hash = hashlib.sha256(
                    json.dumps(
                        arguments, sort_keys=True, separators=(",", ":"),
                    ).encode()
                ).hexdigest()[:16]
                arguments_hash_method = "json_dumps_fallback"
        else:
            arguments_hash = hash_text("")
        tool_output_hash = hash_text(result_text) if result_text else hash_text("")

        # v2.0: Extract justification and compute Receipt Triad
        justification = arguments.get("_justification")
        if isinstance(justification, str):
            justification_stripped = True
        else:
            justification = None
            justification_stripped = False

        triad = compute_receipt_triad(original_name, arguments, justification)

        extensions: dict[str, Any] = {
            "gateway": {
                "server_name": server_name,
                "tool_name": original_name,
                "prefixed_name": prefixed_name,
                "decision": decision.decision,
                "boundary_type": decision.boundary_type,
                "arguments_hash": arguments_hash,
                "arguments_hash_method": arguments_hash_method,
                "tool_output_hash": tool_output_hash,
                "downstream_is_error": downstream_is_error,
            },
            # v2.0: Receipt Triad and structured records
            # NOTE: action.args stores only the arguments_hash (not raw
            # args) because MCP tool arguments may contain floats which
            # are incompatible with RFC 8785 canonical JSON used for
            # fingerprint computation.  Raw args are recoverable from
            # the receipt's inputs.context field.
            "gateway_v2": {
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

        # Block G: embed reasoning evaluation in gateway_v2
        # Use for_signing=True to convert floats to integer basis points
        # for RFC 8785 canonical JSON compatibility (extensions are hashed).
        if reasoning_evaluation is not None:
            from sanna.gateway.receipt_v2 import (
                reasoning_evaluation_to_dict,
            )

            extensions["gateway_v2"]["reasoning_evaluation"] = (
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
            halt_event=halt_event,
            authority_decisions=authority_decisions,
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
    )

    import asyncio
    asyncio.run(gateway.run_stdio())
