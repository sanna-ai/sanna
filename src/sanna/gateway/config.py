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

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

# Valid policy values for default_policy and per-tool overrides
_VALID_POLICIES = frozenset({"can_execute", "must_escalate", "cannot_execute"})

# Pattern for ${VAR_NAME} interpolation
_ENV_VAR_PATTERN = re.compile(r"\$\{([^}]+)\}")


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
        raw = yaml.safe_load(config_file.read_text())
    except yaml.YAMLError as e:
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

    receipt_store = ""
    receipt_store_raw = gw_raw.get("receipt_store")
    if receipt_store_raw:
        receipt_store = _resolve_path(str(receipt_store_raw), config_dir)
        Path(receipt_store).mkdir(parents=True, exist_ok=True)

    escalation_timeout = float(gw_raw.get("escalation_timeout", 300))
    max_pending_escalations = int(
        gw_raw.get("max_pending_escalations", 100),
    )
    circuit_breaker_cooldown = float(
        gw_raw.get("circuit_breaker_cooldown", 60),
    )
    transport = str(gw_raw.get("transport", "stdio"))

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
        receipt_store=receipt_store,
        escalation_timeout=escalation_timeout,
        max_pending_escalations=max_pending_escalations,
        circuit_breaker_cooldown=circuit_breaker_cooldown,
        downstreams=downstreams,
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

    if "_" in name:
        raise GatewayConfigError(
            f"{prefix}: downstream name '{name}' must not contain "
            f"underscores (reserved for tool namespace separator). "
            f"Use hyphens instead: '{name.replace('_', '-')}'"
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
