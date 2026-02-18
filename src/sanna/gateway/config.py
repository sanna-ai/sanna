"""Gateway YAML config loader and validator (Block D).

Parses ``gateway.yaml`` into validated dataclasses, resolves environment
variables in ``env`` blocks, expands paths, validates required fields,
and provides a policy cascade resolver.

Config shape::

    gateway:
      transport: stdio
      constitution: ./constitutions/openclaw-personal.yaml
      constitution_public_key: ~/.sanna/keys/author.pub  # optional
      signing_key: ~/.sanna/keys/gateway.pem
      receipt_store: ./receipts/
      escalation_timeout: 300
      circuit_breaker_cooldown: 60  # optional, seconds

    downstream:
      - name: notion
        command: npx
        args: ["-y", "@notionhq/notion-mcp-server"]
        env:
          NOTION_API_KEY: "${NOTION_API_KEY}"
        default_policy: can_execute
        tools:
          "notion-update-page":
            policy: must_escalate
            reason: "Page mutations require approval"
"""

from __future__ import annotations

import logging
import ipaddress
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

logger = logging.getLogger("sanna.gateway.config")

# Config fields that are parsed but not yet used by the gateway runtime.
# Their presence in YAML is accepted but produces a WARNING.
_UNUSED_CONFIG_FIELDS = frozenset({"transport", "receipt_store_mode"})

# Valid policy values for default_policy and per-tool overrides
_VALID_POLICIES = frozenset({"can_execute", "must_escalate", "cannot_execute"})

# Pattern for ${VAR_NAME} interpolation
_ENV_VAR_PATTERN = re.compile(r"\$\{([^}]+)\}")

# SSRF-blocked IP ranges not always covered by ipaddress.is_private
_CGNAT_NETWORK = ipaddress.ip_network("100.64.0.0/10")
_NAT64_NETWORK = ipaddress.ip_network("64:ff9b::/96")


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class GatewayConfigError(Exception):
    """Raised when the gateway config is invalid."""


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class ToolPolicyConfig:
    """Per-tool policy override from config."""
    policy: str
    reason: str = ""


@dataclass
class DownstreamConfig:
    """Configuration for a single downstream MCP server."""
    name: str
    command: str
    args: list[str] = field(default_factory=list)
    env: dict[str, str] | None = None
    default_policy: str = "can_execute"
    timeout: float = 30.0
    tools: dict[str, ToolPolicyConfig] = field(default_factory=dict)
    optional: bool = False


@dataclass
class RedactionConfig:
    """PII redaction controls for receipt storage.

    When enabled, the gateway redacts specified fields from receipts
    before writing them to disk.  Hashes are always computed on the
    FULL (unredacted) content first, so the receipt signature covers
    the original data.  The stored copy replaces raw values with a
    ``[REDACTED — SHA-256: ...]`` placeholder.

    Attributes:
        enabled: Whether redaction is active.  ``False`` by default.
        mode: ``"hash_only"`` replaces content with its SHA-256 hash.
            ``"pattern_redact"`` is reserved for future regex-based
            PII detection.
        fields: Receipt fields to redact.  Supported values:
            ``"arguments"`` (inputs.context) and ``"result_text"``
            (outputs.output).
    """
    enabled: bool = False
    mode: str = "hash_only"
    fields: list[str] = field(
        default_factory=lambda: ["arguments", "result_text"],
    )


@dataclass
class GatewayConfig:
    """Top-level gateway configuration."""
    transport: str = "stdio"
    constitution_path: str = ""
    signing_key_path: str = ""
    constitution_public_key_path: str = ""
    receipt_store: str = ""
    escalation_timeout: float = 300.0
    max_pending_escalations: int = 100
    circuit_breaker_cooldown: float = 60.0
    downstreams: list[DownstreamConfig] = field(default_factory=list)
    # Block E v2: escalation hardening
    gateway_secret_path: str = ""
    escalation_persist_path: str = ""
    approval_requires_reason: bool = False
    token_delivery: list[str] = field(
        default_factory=lambda: ["stderr"],
    )
    # CRIT-01: webhook delivery + configurable token expiry
    approval_webhook_url: str = ""
    token_expiry_seconds: int = 900
    # Block H: constitution signature verification
    require_constitution_sig: bool = True
    # Block G: PII redaction
    redaction: RedactionConfig = field(
        default_factory=RedactionConfig,
    )
    # Block G: receipt store mode
    receipt_store_mode: str = "filesystem"


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------

def load_gateway_config(config_path: str) -> GatewayConfig:
    """Load and validate a gateway YAML config file.

    Args:
        config_path: Path to the YAML config file.

    Returns:
        A validated ``GatewayConfig``.

    Raises:
        GatewayConfigError: If the config is invalid or missing
            required fields.
        FileNotFoundError: If the config file does not exist.
    """
    config_file = Path(config_path).resolve()
    if not config_file.is_file():
        raise GatewayConfigError(
            f"Config file not found: {config_path}"
        )

    config_dir = config_file.parent

    try:
        from sanna.utils.safe_yaml import safe_yaml_load
        raw = safe_yaml_load(config_file.read_text())
    except (yaml.YAMLError, ValueError) as e:
        raise GatewayConfigError(
            f"Invalid YAML in config file: {e}"
        ) from e

    if not isinstance(raw, dict):
        raise GatewayConfigError(
            "Config file must contain a YAML mapping (got "
            f"{type(raw).__name__})"
        )

    # -- gateway section --
    gw_raw = raw.get("gateway")
    if not isinstance(gw_raw, dict):
        gw_raw = {}

    # Warn about unused config fields
    for field_name in _UNUSED_CONFIG_FIELDS:
        if field_name in gw_raw:
            logger.warning(
                "Config field '%s' is not yet supported and will be ignored.",
                field_name,
            )

    constitution_raw = gw_raw.get("constitution")
    if not constitution_raw:
        raise GatewayConfigError(
            "Missing required field: gateway.constitution"
        )
    constitution_path = _resolve_path(str(constitution_raw), config_dir)
    if not Path(constitution_path).is_file():
        raise GatewayConfigError(
            f"Constitution file not found: {constitution_raw} "
            f"(resolved to {constitution_path})"
        )

    signing_key_raw = gw_raw.get("signing_key")
    if not signing_key_raw:
        raise GatewayConfigError(
            "Missing required field: gateway.signing_key"
        )
    signing_key_path = _resolve_path(str(signing_key_raw), config_dir)
    if not Path(signing_key_path).is_file():
        raise GatewayConfigError(
            f"Signing key file not found: {signing_key_raw} "
            f"(resolved to {signing_key_path})"
        )

    # Optional constitution public key for signature verification
    constitution_public_key_path = ""
    cpk_raw = gw_raw.get("constitution_public_key")
    if cpk_raw:
        constitution_public_key_path = _resolve_path(
            str(cpk_raw), config_dir,
        )
        if not Path(constitution_public_key_path).is_file():
            raise GatewayConfigError(
                f"Constitution public key file not found: {cpk_raw} "
                f"(resolved to {constitution_public_key_path})"
            )

    # Optional: require cryptographic constitution signature verification
    require_constitution_sig = bool(
        gw_raw.get("require_constitution_sig", True)
    )

    receipt_store = ""
    receipt_store_raw = gw_raw.get("receipt_store")
    if receipt_store_raw:
        receipt_store = _resolve_path(str(receipt_store_raw), config_dir)
        Path(receipt_store).mkdir(parents=True, exist_ok=True)

    _valid_store_modes = {"filesystem", "sqlite", "both"}
    receipt_store_mode = str(gw_raw.get("receipt_store_mode", "filesystem"))
    if receipt_store_mode not in _valid_store_modes:
        raise GatewayConfigError(
            f"Invalid receipt_store_mode: '{receipt_store_mode}'. "
            f"Must be one of: {', '.join(sorted(_valid_store_modes))}"
        )

    escalation_timeout = float(gw_raw.get("escalation_timeout", 300))
    max_pending_escalations = int(
        gw_raw.get("max_pending_escalations", 100),
    )
    circuit_breaker_cooldown = float(
        gw_raw.get("circuit_breaker_cooldown", 60),
    )
    transport = str(gw_raw.get("transport", "stdio"))

    # Block E v2: escalation hardening config
    gateway_secret_path = ""
    gsp_raw = gw_raw.get("gateway_secret_path")
    if gsp_raw:
        gateway_secret_path = _resolve_path(str(gsp_raw), config_dir)

    escalation_persist_path = ""
    epp_raw = gw_raw.get("escalation_persist_path")
    if epp_raw:
        escalation_persist_path = _resolve_path(str(epp_raw), config_dir)

    approval_requires_reason = bool(
        gw_raw.get("approval_requires_reason", False),
    )

    _valid_delivery = {"stderr", "file", "log", "callback", "webhook"}
    token_delivery_raw = gw_raw.get("token_delivery", ["stderr"])
    if isinstance(token_delivery_raw, str):
        token_delivery_raw = [token_delivery_raw]
    token_delivery = [str(d) for d in token_delivery_raw]
    for d in token_delivery:
        if d not in _valid_delivery:
            raise GatewayConfigError(
                f"Invalid token_delivery method: '{d}'. "
                f"Must be one of: {', '.join(sorted(_valid_delivery))}"
            )

    # CRIT-01: file delivery requires explicit opt-in
    if "file" in token_delivery:
        if os.environ.get("SANNA_INSECURE_FILE_TOKENS") != "1":
            raise GatewayConfigError(
                "File-based token delivery is insecure. Agents with "
                "file-reading tools can self-approve escalations. Set "
                "SANNA_INSECURE_FILE_TOKENS=1 to acknowledge this risk."
            )

    # CRIT-01: webhook URL + token expiry
    approval_webhook_url = str(gw_raw.get("approval_webhook_url", ""))
    if "webhook" in token_delivery and not approval_webhook_url:
        raise GatewayConfigError(
            "approval_webhook_url is required when token_delivery "
            "includes 'webhook'"
        )
    if approval_webhook_url:
        validate_webhook_url(approval_webhook_url)

    token_expiry_seconds = int(
        gw_raw.get("token_expiry_seconds", 900),
    )
    if token_expiry_seconds < 1:
        raise GatewayConfigError(
            "token_expiry_seconds must be a positive integer"
        )

    # -- redaction section --
    redaction = RedactionConfig()
    redaction_raw = gw_raw.get("redaction")
    if isinstance(redaction_raw, dict):
        redaction_enabled = bool(redaction_raw.get("enabled", False))
        redaction_mode = str(redaction_raw.get("mode", "hash_only"))
        if redaction_mode not in ("hash_only", "pattern_redact"):
            raise GatewayConfigError(
                f"Invalid redaction mode: '{redaction_mode}'. "
                f"Must be 'hash_only' or 'pattern_redact'."
            )
        if redaction_mode == "pattern_redact":
            raise GatewayConfigError(
                "pattern_redact mode is not yet implemented. Use hash_only."
            )
        redaction_fields_raw = redaction_raw.get(
            "fields", ["arguments", "result_text"],
        )
        valid_fields = {"arguments", "result_text"}
        redaction_fields = [str(f) for f in redaction_fields_raw]
        for f in redaction_fields:
            if f not in valid_fields:
                raise GatewayConfigError(
                    f"Invalid redaction field: '{f}'. "
                    f"Must be one of: {', '.join(sorted(valid_fields))}"
                )
        redaction = RedactionConfig(
            enabled=redaction_enabled,
            mode=redaction_mode,
            fields=redaction_fields,
        )

    # -- downstream section --
    ds_raw = raw.get("downstream")
    if not ds_raw or not isinstance(ds_raw, list) or len(ds_raw) == 0:
        raise GatewayConfigError(
            "Missing required field: downstream (need at least one entry)"
        )

    downstreams: list[DownstreamConfig] = []
    for idx, ds in enumerate(ds_raw):
        if not isinstance(ds, dict):
            raise GatewayConfigError(
                f"downstream[{idx}]: expected a mapping, "
                f"got {type(ds).__name__}"
            )
        downstreams.append(_parse_downstream(ds, idx))

    return GatewayConfig(
        transport=transport,
        constitution_path=constitution_path,
        signing_key_path=signing_key_path,
        constitution_public_key_path=constitution_public_key_path,
        require_constitution_sig=require_constitution_sig,
        receipt_store=receipt_store,
        escalation_timeout=escalation_timeout,
        max_pending_escalations=max_pending_escalations,
        circuit_breaker_cooldown=circuit_breaker_cooldown,
        downstreams=downstreams,
        gateway_secret_path=gateway_secret_path,
        escalation_persist_path=escalation_persist_path,
        approval_requires_reason=approval_requires_reason,
        token_delivery=token_delivery,
        approval_webhook_url=approval_webhook_url,
        token_expiry_seconds=token_expiry_seconds,
        redaction=redaction,
        receipt_store_mode=receipt_store_mode,
    )


def _parse_downstream(
    raw: dict[str, Any], idx: int,
) -> DownstreamConfig:
    """Parse and validate a single downstream entry."""
    prefix = f"downstream[{idx}]"

    name = raw.get("name")
    if not name:
        raise GatewayConfigError(
            f"{prefix}: missing required field 'name'"
        )
    name = str(name)

    if not re.match(r'^[a-zA-Z0-9_-]+$', name):
        raise GatewayConfigError(
            f"{prefix}: downstream name '{name}' contains invalid "
            f"characters. Use alphanumeric, hyphens, and underscores only."
        )

    command = raw.get("command")
    if not command:
        raise GatewayConfigError(
            f"{prefix}: missing required field 'command'"
        )
    command = str(command)

    args = raw.get("args", [])
    if not isinstance(args, list):
        args = [str(args)]
    else:
        args = [str(a) for a in args]

    # Environment variables — interpolate from os.environ
    env_raw = raw.get("env")
    env: dict[str, str] | None = None
    if isinstance(env_raw, dict):
        env = {}
        for key, value in env_raw.items():
            env[str(key)] = _interpolate_env(str(value), str(key), prefix)

    # timeout
    timeout = float(raw.get("timeout", 30.0))

    # default_policy
    default_policy = str(raw.get("default_policy", "can_execute"))
    if default_policy not in _VALID_POLICIES:
        raise GatewayConfigError(
            f"{prefix}: invalid default_policy '{default_policy}'. "
            f"Must be one of: {', '.join(sorted(_VALID_POLICIES))}"
        )

    # Per-tool policy overrides
    tools_raw = raw.get("tools", {})
    tools: dict[str, ToolPolicyConfig] = {}
    if isinstance(tools_raw, dict):
        for tool_name, tool_cfg in tools_raw.items():
            tool_name = str(tool_name)
            if not isinstance(tool_cfg, dict):
                raise GatewayConfigError(
                    f"{prefix}.tools.{tool_name}: expected a mapping"
                )
            policy = tool_cfg.get("policy")
            if not policy:
                raise GatewayConfigError(
                    f"{prefix}.tools.{tool_name}: "
                    f"missing required field 'policy'"
                )
            policy = str(policy)
            if policy not in _VALID_POLICIES:
                raise GatewayConfigError(
                    f"{prefix}.tools.{tool_name}: "
                    f"invalid policy '{policy}'. "
                    f"Must be one of: {', '.join(sorted(_VALID_POLICIES))}"
                )
            reason = str(tool_cfg.get("reason", ""))
            tools[tool_name] = ToolPolicyConfig(
                policy=policy, reason=reason,
            )

    # optional
    optional = bool(raw.get("optional", False))

    return DownstreamConfig(
        name=name,
        command=command,
        args=args,
        env=env,
        default_policy=default_policy,
        timeout=timeout,
        tools=tools,
        optional=optional,
    )


# ---------------------------------------------------------------------------
# Environment variable interpolation
# ---------------------------------------------------------------------------

def _interpolate_env(
    value: str, env_key: str, prefix: str,
) -> str:
    """Resolve ``${VAR_NAME}`` patterns from ``os.environ``.

    Only called for values inside ``env`` blocks.

    Raises:
        GatewayConfigError: If a referenced env var is not set.
    """
    def _replacer(match: re.Match) -> str:
        var_name = match.group(1)
        resolved = os.environ.get(var_name)
        if resolved is None:
            raise GatewayConfigError(
                f"{prefix}.env.{env_key}: environment variable "
                f"'{var_name}' is not set"
            )
        return resolved

    return _ENV_VAR_PATTERN.sub(_replacer, value)


# ---------------------------------------------------------------------------
# Path resolution
# ---------------------------------------------------------------------------

def _resolve_path(raw_path: str, config_dir: Path) -> str:
    """Expand ``~`` and resolve relative paths against ``config_dir``."""
    expanded = Path(os.path.expanduser(raw_path))
    if not expanded.is_absolute():
        expanded = config_dir / expanded
    return str(expanded.resolve())


# ---------------------------------------------------------------------------
# CRIT-01: Webhook URL SSRF validation
# ---------------------------------------------------------------------------

def _is_blocked_ip(addr: "ipaddress.IPv4Address | ipaddress.IPv6Address") -> str | None:
    """Return a human-readable reason if *addr* is in a blocked range, else ``None``."""
    import ipaddress as _ipa  # noqa: F811 — re-import is harmless; keeps function self-contained

    # Cloud metadata endpoint (169.254.169.254) — checked before
    # link-local and private since it is a subset of both ranges
    _metadata_addrs = {
        _ipa.ip_address("169.254.169.254"),
        _ipa.ip_address("fd00::c0a8:a9fe"),  # IPv6 alias
    }
    if addr in _metadata_addrs:
        return f"cloud metadata endpoint: {addr}"

    if addr.is_loopback:
        return f"loopback address: {addr}"

    if addr.is_link_local:
        return f"link-local address: {addr}"

    if addr.is_multicast:
        return f"multicast address: {addr}"

    if addr.is_private:
        return f"private/RFC-1918 address: {addr}"

    # CGNAT / Shared Address Space (RFC 6598) — not flagged by
    # Python's ipaddress.is_private on all versions
    if isinstance(addr, ipaddress.IPv4Address) and addr in _CGNAT_NETWORK:
        return f"CGNAT/shared address: {addr}"
    if isinstance(addr, ipaddress.IPv6Address) and addr in _NAT64_NETWORK:
        return f"NAT64 well-known prefix: {addr}"

    # Check IPv4-mapped IPv6 addresses (::ffff:x.x.x.x)
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        mapped_reason = _is_blocked_ip(addr.ipv4_mapped)
        if mapped_reason:
            return f"IPv4-mapped: {mapped_reason}"

    return None


def validate_webhook_url(url: str) -> None:
    """Validate a webhook URL, rejecting SSRF-prone targets.

    Rejects:
    - Non-HTTPS schemes (unless ``SANNA_ALLOW_INSECURE_WEBHOOK=1`` for
      ``http://localhost`` and ``http://127.0.0.1`` only)
    - localhost / 127.0.0.0/8 / ::1
    - RFC 1918 addresses (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
    - Link-local (169.254.0.0/16, fe80::/10)
    - Multicast addresses
    - Cloud metadata endpoints (169.254.169.254)
    - DNS hostnames that resolve to any blocked IP range

    Raises:
        GatewayConfigError: If the URL fails SSRF validation.
    """
    import ipaddress
    import socket
    from urllib.parse import urlparse

    try:
        parsed = urlparse(url)
    except Exception as exc:
        raise GatewayConfigError(
            f"Invalid webhook URL: {exc}"
        ) from exc

    # Scheme check — require HTTPS by default (SEC-2)
    if parsed.scheme not in ("http", "https"):
        raise GatewayConfigError(
            f"Webhook URL must use http or https scheme, "
            f"got '{parsed.scheme}'"
        )

    hostname = parsed.hostname or ""
    if not hostname:
        raise GatewayConfigError(
            "Webhook URL has no hostname"
        )

    # SEC-2: Enforce HTTPS unless insecure webhook override is set
    if parsed.scheme == "http":
        _allow_insecure = os.environ.get("SANNA_ALLOW_INSECURE_WEBHOOK") == "1"
        _is_local = hostname.lower() in ("localhost", "127.0.0.1", "[::1]", "::1")
        if _allow_insecure and _is_local:
            logger.critical(
                "SECURITY WARNING: Allowing insecure HTTP webhook to %s "
                "because SANNA_ALLOW_INSECURE_WEBHOOK=1 is set. "
                "Do NOT use this in production.",
                hostname,
            )
        else:
            raise GatewayConfigError(
                f"Webhook URL must use https:// scheme. "
                f"Got http://{hostname}. "
                f"Set SANNA_ALLOW_INSECURE_WEBHOOK=1 to allow "
                f"http://localhost or http://127.0.0.1 for local development only."
            )
        # Even with insecure override, localhost is allowed — skip
        # further IP validation since we know it's local.
        return

    # Localhost check (hostname string)
    if hostname.lower() in ("localhost", "127.0.0.1", "::1", "0.0.0.0"):
        raise GatewayConfigError(
            f"Webhook URL must not point to localhost: {hostname}"
        )

    # Try to parse as IP address for range checks
    try:
        addr = ipaddress.ip_address(hostname)
    except ValueError:
        # Not an IP literal — resolve DNS and check all returned addresses
        # (SEC-6: DNS rebinding protection)
        try:
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                future = pool.submit(
                    socket.getaddrinfo,
                    hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM,
                )
                try:
                    addrinfos = future.result(timeout=5)
                except concurrent.futures.TimeoutError:
                    raise GatewayConfigError(
                        f"DNS resolution timed out for webhook hostname '{hostname}'"
                    ) from None
        except socket.gaierror as exc:
            raise GatewayConfigError(
                f"Webhook URL hostname '{hostname}' failed DNS resolution: {exc}"
            ) from exc

        for family, _type, _proto, _canonname, sockaddr in addrinfos:
            ip_str = sockaddr[0]
            try:
                resolved_addr = ipaddress.ip_address(ip_str)
            except ValueError:
                continue
            reason = _is_blocked_ip(resolved_addr)
            if reason is not None:
                raise GatewayConfigError(
                    f"Webhook URL hostname '{hostname}' resolves to "
                    f"blocked {reason}"
                )
        return

    # IP literal — check directly
    reason = _is_blocked_ip(addr)
    if reason is not None:
        raise GatewayConfigError(
            f"Webhook URL must not point to {reason}"
        )


# ---------------------------------------------------------------------------
# Policy cascade resolver
# ---------------------------------------------------------------------------

def resolve_tool_policy(
    tool_name: str,
    downstream: DownstreamConfig,
) -> str | None:
    """Resolve the effective policy for a tool using the cascade.

    Priority:
        1. Per-tool override in ``downstream.tools``
        2. ``downstream.default_policy``
        3. Implicit default: ``"can_execute"``

    Returns the policy string (``"can_execute"``, ``"cannot_execute"``,
    or ``"must_escalate"``), or ``None`` if the effective policy is
    ``"can_execute"`` (meaning: fall through to constitution evaluation).

    The gateway enforcement layer calls this on every tool call.  A
    non-None return value acts as a policy override that takes precedence
    over constitution authority boundary evaluation.
    """
    # 1. Per-tool override
    tool_cfg = downstream.tools.get(tool_name)
    if tool_cfg is not None:
        return tool_cfg.policy

    # 2. Server default_policy
    if downstream.default_policy != "can_execute":
        return downstream.default_policy

    # 3. Implicit default — no override, fall through to constitution
    return None


def build_policy_overrides(downstream: DownstreamConfig) -> dict[str, str]:
    """Build a flat policy overrides dict for ``SannaGateway``.

    Merges per-tool overrides with the server default_policy.
    Only includes entries that differ from the implicit default
    (``"can_execute"``), since the gateway's enforcement layer
    falls through to constitution evaluation for unspecified tools.
    """
    overrides: dict[str, str] = {}

    # Per-tool overrides always take precedence
    for tool_name, tool_cfg in downstream.tools.items():
        overrides[tool_name] = tool_cfg.policy

    return overrides
