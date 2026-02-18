"""Gateway migration — wrap existing MCP configs behind sanna-gateway.

Reads an MCP client's config file, extracts all server entries,
generates a ``gateway.yaml`` with those servers as downstreams,
creates a signed constitution and gateway keypair, then rewrites
the client config to point at the single ``sanna-gateway`` entry.

One command: existing MCP setup becomes governed.

Usage::

    sanna-gateway migrate --client claude-desktop
    sanna-gateway migrate --client claude-desktop --dry-run
    sanna-gateway migrate --auto
    sanna-gateway migrate --template openclaw-personal
"""

from __future__ import annotations

import importlib.resources
import json
import logging

from ..utils.safe_json import safe_json_loads
import os
import platform
import re
import shutil
import sys
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger("sanna.gateway.migrate")


# ---------------------------------------------------------------------------
# Reasoning constitution comment (v0.11.0)
# ---------------------------------------------------------------------------

_REASONING_COMMENT = """\

# =============================================================================
# Reasoning governance (v1.1 — optional)
# =============================================================================
#
# Uncomment and configure to enable reasoning receipt generation.
# When enabled, governed tool calls require a _justification parameter
# and reasoning is evaluated before forwarding.
#
# reasoning:
#   require_justification_for:
#     - must_escalate
#     - cannot_execute
#
#   on_missing_justification: block    # block | escalate | allow
#   on_check_error: block              # block | escalate | allow
#
#   checks:
#     glc_002_minimum_substance:
#       enabled: true
#       min_length: 20
#
#     glc_003_no_parroting:
#       enabled: true
#       blocklist:
#         - "because you asked"
#         - "you told me to"
#         - "you requested"
#
#     glc_005_llm_coherence:
#       enabled: true
#       enabled_for:
#         - must_escalate
#       timeout_ms: 2000
#       score_threshold: 0.6
#       # Model configured via SANNA_LLM_MODEL environment variable
#
#   evaluate_before_escalation: true
#   auto_deny_on_reasoning_failure: false
"""


def _append_reasoning_comment(constitution_path: Path) -> None:
    """Append the commented reasoning section to a constitution file.

    Idempotent — skips if the file already contains the reasoning marker.
    """
    text = constitution_path.read_text(encoding="utf-8")
    if "Reasoning governance" in text:
        return
    # Atomic rewrite instead of append to avoid partial writes
    from ..utils.safe_io import atomic_write_text_sync
    atomic_write_text_sync(constitution_path, text + _REASONING_COMMENT)


# ---------------------------------------------------------------------------
# Atomic file I/O
# ---------------------------------------------------------------------------

def _atomic_write(filepath: Path, content: str) -> None:
    """Write *content* to *filepath* atomically with symlink protection.

    Delegates to ``sanna.utils.safe_io.atomic_write_sync`` which provides
    randomised temp names, symlink rejection, ``os.fsync``, and
    ``os.replace`` atomicity.
    """
    from sanna.utils.safe_io import atomic_write_sync
    atomic_write_sync(filepath, content, mode=0o600)


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class ServerEntry:
    """Parsed MCP server entry from a client config."""

    name: str
    command: str
    args: list[str] = field(default_factory=list)
    env: dict[str, str] = field(default_factory=dict)
    transport_type: str = "stdio"
    extra_fields: dict[str, Any] = field(default_factory=dict)


@dataclass
class MigrationPlan:
    """What the migration will do, computed before execution."""

    client_name: str
    config_path: Path
    backup_path: Path
    servers: list[ServerEntry]
    migratable: list[ServerEntry]
    skipped: list[tuple[ServerEntry, str]]
    sanna_dir: Path
    gateway_config_path: Path
    constitution_template: str
    constitution_path: Path
    keys_dir: Path
    receipt_store_dir: Path
    detected_secrets: dict[str, str]
    already_migrated: bool
    keypair_exists: bool
    constitution_exists: bool


@dataclass
class MigrationResult:
    """Result of executing a migration plan."""

    success: bool
    plan: MigrationPlan
    private_key_path: Path | None = None
    public_key_path: Path | None = None
    warnings: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Gateway constitution templates
# ---------------------------------------------------------------------------

_GATEWAY_TEMPLATES: dict[str, str] = {
    "openclaw-personal": "openclaw_personal.yaml",
    "openclaw-developer": "openclaw_developer.yaml",
    "cowork-personal": "cowork_personal.yaml",
    "cowork-team": "cowork_team.yaml",
    "claude-code-standard": "claude_code_standard.yaml",
}

# Default template per client
_CLIENT_DEFAULT_TEMPLATE: dict[str, str] = {
    "claude-desktop": "cowork-personal",
    "claude-code": "claude-code-standard",
    "cursor": "claude-code-standard",
    "windsurf": "claude-code-standard",
}


def load_gateway_template(template_name: str) -> str:
    """Load a gateway constitution template from package data.

    Returns the raw YAML content as a string.

    Raises:
        ValueError: If the template name is not recognized.
    """
    filename = _GATEWAY_TEMPLATES.get(template_name)
    if filename is None:
        raise ValueError(
            f"Unknown template: {template_name!r}. "
            f"Available: {', '.join(sorted(_GATEWAY_TEMPLATES))}"
        )
    ref = importlib.resources.files("sanna.templates").joinpath(filename)
    return ref.read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# Client adapters
# ---------------------------------------------------------------------------

class ClientAdapter(ABC):
    """Base class for MCP client config adapters."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Client identifier (e.g., ``'claude-desktop'``)."""
        ...

    @abstractmethod
    def config_paths(self) -> list[Path]:
        """Possible config file paths for this platform (priority order)."""
        ...

    @abstractmethod
    def parse_servers(self, config_data: dict) -> list[ServerEntry]:
        """Extract MCP server entries from the parsed config."""
        ...

    @abstractmethod
    def build_migrated_config(
        self,
        original_config: dict,
        gateway_command: str,
        gateway_args: list[str],
    ) -> dict:
        """Build updated client config with sanna-gateway as single entry.

        Preserves any non-mcpServers keys from the original config.
        """
        ...

    def detect_config(self) -> Path | None:
        """Find the first existing config file for this client."""
        for p in self.config_paths():
            if p.exists():
                return p
        return None

    def is_already_migrated(self, config_data: dict) -> bool:
        """Check if config already has a sanna-gateway entry."""
        servers = config_data.get("mcpServers", {})
        return "sanna-gateway" in servers


class ClaudeDesktopAdapter(ClientAdapter):
    """Adapter for Claude Desktop (macOS / Linux / Windows)."""

    @property
    def name(self) -> str:
        return "claude-desktop"

    def config_paths(self) -> list[Path]:
        system = platform.system()
        if system == "Darwin":
            return [
                Path.home()
                / "Library"
                / "Application Support"
                / "Claude"
                / "claude_desktop_config.json"
            ]
        elif system == "Linux":
            return [
                Path.home()
                / ".config"
                / "claude"
                / "claude_desktop_config.json"
            ]
        elif system == "Windows":
            appdata = os.environ.get("APPDATA", "")
            if appdata:
                return [
                    Path(appdata) / "Claude" / "claude_desktop_config.json"
                ]
        return []

    def parse_servers(self, config_data: dict) -> list[ServerEntry]:
        servers: list[ServerEntry] = []
        for name, entry in config_data.get("mcpServers", {}).items():
            if not isinstance(entry, dict):
                continue
            servers.append(ServerEntry(
                name=name,
                command=entry.get("command", ""),
                args=entry.get("args", []),
                env=entry.get("env", {}),
                transport_type="stdio",
            ))
        return servers

    def build_migrated_config(
        self,
        original_config: dict,
        gateway_command: str,
        gateway_args: list[str],
    ) -> dict:
        config = {
            k: v for k, v in original_config.items() if k != "mcpServers"
        }
        config["mcpServers"] = {
            "sanna-gateway": {
                "command": gateway_command,
                "args": gateway_args,
            },
        }
        return config


class ClaudeCodeAdapter(ClientAdapter):
    """Adapter for Claude Code (stub — coming in v0.12.1)."""

    @property
    def name(self) -> str:
        return "claude-code"

    def config_paths(self) -> list[Path]:
        raise NotImplementedError(
            "Claude Code adapter coming in v0.12.1. "
            "Use --client claude-desktop for now."
        )

    def parse_servers(self, config_data: dict) -> list[ServerEntry]:
        raise NotImplementedError

    def build_migrated_config(
        self, original_config: dict,
        gateway_command: str, gateway_args: list[str],
    ) -> dict:
        raise NotImplementedError


class CursorAdapter(ClientAdapter):
    """Adapter for Cursor (stub — coming in v0.12.1)."""

    @property
    def name(self) -> str:
        return "cursor"

    def config_paths(self) -> list[Path]:
        raise NotImplementedError(
            "Cursor adapter coming in v0.12.1. "
            "Use --client claude-desktop for now."
        )

    def parse_servers(self, config_data: dict) -> list[ServerEntry]:
        raise NotImplementedError

    def build_migrated_config(
        self, original_config: dict,
        gateway_command: str, gateway_args: list[str],
    ) -> dict:
        raise NotImplementedError


class WindsurfAdapter(ClientAdapter):
    """Adapter for Windsurf (stub — coming in v0.12.1)."""

    @property
    def name(self) -> str:
        return "windsurf"

    def config_paths(self) -> list[Path]:
        raise NotImplementedError(
            "Windsurf adapter coming in v0.12.1. "
            "Use --client claude-desktop for now."
        )

    def parse_servers(self, config_data: dict) -> list[ServerEntry]:
        raise NotImplementedError

    def build_migrated_config(
        self, original_config: dict,
        gateway_command: str, gateway_args: list[str],
    ) -> dict:
        raise NotImplementedError


# Adapter registry
_ADAPTERS: dict[str, type[ClientAdapter]] = {
    "claude-desktop": ClaudeDesktopAdapter,
    "claude-code": ClaudeCodeAdapter,
    "cursor": CursorAdapter,
    "windsurf": WindsurfAdapter,
}


def get_adapter(client_name: str) -> ClientAdapter:
    """Get adapter instance by client name.

    Raises:
        ValueError: If client_name is not recognized.
    """
    cls = _ADAPTERS.get(client_name)
    if cls is None:
        raise ValueError(
            f"Unknown client: {client_name!r}. "
            f"Supported: {', '.join(sorted(_ADAPTERS))}"
        )
    return cls()


def detect_installed_clients() -> list[tuple[str, Path]]:
    """Auto-detect installed MCP clients by checking config paths.

    Returns list of ``(client_name, config_path)`` for each client
    whose config file exists.
    """
    found: list[tuple[str, Path]] = []
    for name, cls in _ADAPTERS.items():
        try:
            adapter = cls()
            path = adapter.detect_config()
            if path is not None:
                found.append((name, path))
        except NotImplementedError:
            pass
    return found


# ---------------------------------------------------------------------------
# Secret detection
# ---------------------------------------------------------------------------

_SECRET_PREFIXES = (
    "sk-", "ntn_", "xoxb-", "xoxp-", "ghp_", "ghs_",
    "Bearer ", "Basic ",
)


def detect_secrets(env: dict[str, str]) -> dict[str, str]:
    """Detect likely hardcoded secrets in env vars.

    Returns ``{var_name: detected_value}`` for values that look
    like secrets. Uses heuristics: known prefixes, length > 20.

    Already-interpolated values (``${VAR}``) are skipped.
    """
    detected: dict[str, str] = {}
    for key, value in env.items():
        if not value or value.startswith("${"):
            continue
        if len(value) > 20:
            detected[key] = value
            continue
        for prefix in _SECRET_PREFIXES:
            if value.startswith(prefix):
                detected[key] = value
                break
    return detected


# ---------------------------------------------------------------------------
# Keypair detection
# ---------------------------------------------------------------------------

def _find_gateway_keypair(keys_dir: Path) -> tuple[Path, Path] | None:
    """Find an existing keypair with label 'gateway' in keys_dir.

    Checks ``.meta.json`` sidecars for ``"label": "gateway"``.
    Returns ``(private_key_path, public_key_path)`` or ``None``.
    """
    if not keys_dir.is_dir():
        return None
    for meta_path in keys_dir.glob("*.meta.json"):
        try:
            meta = safe_json_loads(meta_path.read_text())
            if meta.get("label") == "gateway":
                key_id = meta.get("key_id", "")
                priv = keys_dir / f"{key_id}.key"
                pub = keys_dir / f"{key_id}.pub"
                if priv.is_file() and pub.is_file():
                    return priv, pub
        except (json.JSONDecodeError, ValueError, OSError):
            continue
    return None


# ---------------------------------------------------------------------------
# Plan
# ---------------------------------------------------------------------------

def plan_migration(
    adapter: ClientAdapter,
    config_path: Path,
    template: str | None = None,
    sanna_dir: Path | None = None,
) -> MigrationPlan:
    """Analyze the client config and build a migration plan.

    Does not modify any files. Returns a plan that can be
    displayed (``--dry-run``) or executed.

    Raises:
        FileNotFoundError: If config_path does not exist.
        json.JSONDecodeError: If config is not valid JSON.
    """
    if not config_path.is_file():
        raise FileNotFoundError(
            f"No {adapter.name} config found at {config_path}"
        )

    config_data = safe_json_loads(config_path.read_text(encoding="utf-8"))

    if template is None:
        template = _CLIENT_DEFAULT_TEMPLATE.get(
            adapter.name, "openclaw-personal",
        )

    if sanna_dir is None:
        sanna_dir = Path.home() / ".sanna"

    servers = adapter.parse_servers(config_data)
    already_migrated = adapter.is_already_migrated(config_data)

    migratable: list[ServerEntry] = []
    skipped: list[tuple[ServerEntry, str]] = []

    for s in servers:
        if s.name == "sanna-gateway":
            skipped.append((s, "already a sanna-gateway entry"))
        elif s.transport_type != "stdio":
            skipped.append((
                s,
                f"transport '{s.transport_type}' not supported "
                f"(gateway supports stdio only)",
            ))
        elif not s.command:
            skipped.append((s, "no command specified"))
        else:
            migratable.append(s)

    # Detect secrets across all migratable servers
    all_secrets: dict[str, str] = {}
    for s in migratable:
        all_secrets.update(detect_secrets(s.env))

    keys_dir = sanna_dir / "keys"
    constitution_dir = sanna_dir / "constitutions"
    receipt_store_dir = sanna_dir / "receipts"
    gateway_config_path = sanna_dir / "gateway.yaml"
    constitution_path = constitution_dir / f"{template}.yaml"

    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
    backup_path = config_path.parent / f"{config_path.name}.backup.{ts}"

    keypair_exists = _find_gateway_keypair(keys_dir) is not None
    constitution_exists = constitution_path.is_file()

    return MigrationPlan(
        client_name=adapter.name,
        config_path=config_path,
        backup_path=backup_path,
        servers=servers,
        migratable=migratable,
        skipped=skipped,
        sanna_dir=sanna_dir,
        gateway_config_path=gateway_config_path,
        constitution_template=template,
        constitution_path=constitution_path,
        keys_dir=keys_dir,
        receipt_store_dir=receipt_store_dir,
        detected_secrets=all_secrets,
        already_migrated=already_migrated,
        keypair_exists=keypair_exists,
        constitution_exists=constitution_exists,
    )


# ---------------------------------------------------------------------------
# Execute
# ---------------------------------------------------------------------------

def execute_migration(
    plan: MigrationPlan,
    *,
    dry_run: bool = False,
) -> MigrationResult:
    """Execute a migration plan.

    If ``dry_run`` is True, no files are written.

    Steps:
        1. Create directories
        2. Generate gateway keypair (if missing)
        3. Copy + sign constitution template (if missing)
        4. Generate gateway.yaml
        5. Backup original client config
        6. Write updated client config
    """
    warnings: list[str] = []

    if dry_run:
        return MigrationResult(
            success=True,
            plan=plan,
            warnings=warnings,
        )

    if not plan.migratable:
        return MigrationResult(
            success=False,
            plan=plan,
            warnings=["No MCP servers found to migrate"],
        )

    # 1. Create directories
    plan.keys_dir.mkdir(parents=True, exist_ok=True)
    plan.receipt_store_dir.mkdir(parents=True, exist_ok=True)
    plan.constitution_path.parent.mkdir(parents=True, exist_ok=True)

    # 2. Generate keypair
    private_key_path: Path | None = None
    public_key_path: Path | None = None

    existing = _find_gateway_keypair(plan.keys_dir)
    if existing is not None:
        private_key_path, public_key_path = existing
        warnings.append(
            f"Using existing gateway keypair: {private_key_path.name}"
        )
    else:
        from sanna.crypto import generate_keypair

        priv, pub = generate_keypair(
            str(plan.keys_dir), label="gateway",
        )
        private_key_path = Path(priv)
        public_key_path = Path(pub)

    # 3. Copy and sign constitution
    if plan.constitution_exists:
        warnings.append(
            f"Using existing constitution: {plan.constitution_path}"
        )
    else:
        content = load_gateway_template(plan.constitution_template)
        _atomic_write(plan.constitution_path, content)

        from sanna.constitution import (
            load_constitution,
            sign_constitution,
            save_constitution,
        )

        constitution = load_constitution(str(plan.constitution_path))
        signed = sign_constitution(
            constitution,
            private_key_path=str(private_key_path),
        )
        save_constitution(signed, str(plan.constitution_path))

        # Append commented reasoning section for v0.11.0 discoverability
        _append_reasoning_comment(plan.constitution_path)

    # 4. Generate gateway.yaml
    gateway_yaml = _build_gateway_yaml(
        plan=plan,
        signing_key_path=private_key_path,
        public_key_path=public_key_path,
    )
    _atomic_write(plan.gateway_config_path, gateway_yaml)

    # 5. Backup original client config
    shutil.copy2(str(plan.config_path), str(plan.backup_path))

    # 6. Write updated client config
    original_config = safe_json_loads(
        plan.config_path.read_text(encoding="utf-8"),
    )
    adapter = get_adapter(plan.client_name)
    new_config = adapter.build_migrated_config(
        original_config=original_config,
        gateway_command="sanna-gateway",
        gateway_args=["--config", str(plan.gateway_config_path)],
    )
    _atomic_write(
        plan.config_path,
        json.dumps(new_config, indent=2) + "\n",
    )

    # Check if sanna-gateway is in PATH
    if shutil.which("sanna-gateway") is None:
        warnings.append(
            "sanna-gateway not found in PATH. "
            "Install with: pip install sanna[mcp]"
        )

    return MigrationResult(
        success=True,
        plan=plan,
        private_key_path=private_key_path,
        public_key_path=public_key_path,
        warnings=warnings,
    )


# ---------------------------------------------------------------------------
# Gateway YAML generation
# ---------------------------------------------------------------------------

def _build_gateway_yaml(
    plan: MigrationPlan,
    signing_key_path: Path | None,
    public_key_path: Path | None = None,
) -> str:
    """Build the gateway.yaml content from a migration plan.

    Uses relative paths for the constitution (relative to the
    gateway.yaml location) and absolute paths for the signing key
    and receipt store.
    """
    import yaml

    # Compute relative constitution path from gateway.yaml dir
    try:
        const_rel = os.path.relpath(
            plan.constitution_path, plan.gateway_config_path.parent,
        )
    except ValueError:
        # On Windows, relpath fails across drives
        const_rel = str(plan.constitution_path)

    gateway_section: dict[str, Any] = {
        "transport": "stdio",
        "constitution": const_rel,
        "signing_key": str(signing_key_path) if signing_key_path else "",
        "receipt_store": str(plan.receipt_store_dir),
        "escalation_timeout": 300,
    }
    if public_key_path:
        gateway_section["constitution_public_key"] = str(public_key_path)

    downstreams: list[dict[str, Any]] = []
    for server in plan.migratable:
        # Sanitize: underscores reserved for {server}_{tool} namespacing
        sanitized_name = server.name.replace("_", "-")
        entry: dict[str, Any] = {
            "name": sanitized_name,
            "command": server.command,
        }
        if server.args:
            entry["args"] = server.args
        if server.env:
            # Replace detected secrets with ${VAR} interpolation
            env: dict[str, str] = {}
            for key, value in server.env.items():
                if key in plan.detected_secrets:
                    env[key] = f"${{{key}}}"
                else:
                    env[key] = value
            entry["env"] = env
        entry["default_policy"] = "can_execute"
        entry["timeout"] = 30
        downstreams.append(entry)

    config = {
        "gateway": gateway_section,
        "downstream": downstreams,
    }

    return yaml.dump(
        config,
        default_flow_style=False,
        sort_keys=False,
        allow_unicode=True,
    )


# ---------------------------------------------------------------------------
# Output formatting
# ---------------------------------------------------------------------------

def format_plan(plan: MigrationPlan, result: MigrationResult | None = None) -> str:
    """Format a migration plan (and optional result) for display."""
    lines: list[str] = []

    if plan.already_migrated:
        lines.append(
            "Note: Config already contains a sanna-gateway entry. "
            "Migration will overwrite it."
        )
        lines.append("")

    if not plan.migratable:
        lines.append("No MCP servers found to migrate.")
        if plan.servers:
            lines.append(f"  ({len(plan.servers)} server(s) skipped)")
        return "\n".join(lines)

    # Servers being migrated
    lines.append(f"Migrating {len(plan.migratable)} MCP server(s):")
    for s in plan.migratable:
        cmd_summary = s.command
        if s.args:
            cmd_summary += " " + " ".join(s.args)
        lines.append(f"  - {s.name} ({cmd_summary})")

    if plan.skipped:
        lines.append("")
        lines.append(f"Skipping {len(plan.skipped)} server(s):")
        for s, reason in plan.skipped:
            lines.append(f"  - {s.name}: {reason}")

    # Generated files
    lines.append("")
    lines.append("Generated:")
    lines.append(
        f"  {plan.gateway_config_path} "
        f"({len(plan.migratable)} downstream(s))"
    )
    if plan.keypair_exists:
        lines.append(f"  {plan.keys_dir} (existing keypair)")
    else:
        if result and result.private_key_path:
            lines.append(
                f"  {result.private_key_path} (new keypair)"
            )
        else:
            lines.append(f"  {plan.keys_dir}/<key_id>.key (new keypair)")
    if plan.constitution_exists:
        lines.append(f"  {plan.constitution_path} (existing)")
    else:
        lines.append(
            f"  {plan.constitution_path} "
            f"(signed, template: {plan.constitution_template})"
        )

    # Client config update
    lines.append("")
    lines.append("Updated:")
    lines.append(f"  {plan.config_path}")
    lines.append("")
    lines.append("Backup:")
    lines.append(f"  {plan.backup_path}")

    # Secret detection warnings
    if plan.detected_secrets:
        lines.append("")
        lines.append(
            "Detected hardcoded secrets "
            "(replaced with ${VAR} in gateway.yaml):"
        )
        for var_name, value in plan.detected_secrets.items():
            # Truncate long values for display
            display = value if len(value) <= 20 else value[:12] + "..."
            lines.append(
                f'  {var_name} -> export {var_name}="{display}"'
            )

    # Warnings from execution
    if result and result.warnings:
        lines.append("")
        for w in result.warnings:
            lines.append(f"Warning: {w}")

    # Next steps
    lines.append("")
    lines.append("Next steps:")
    step = 1
    if plan.detected_secrets:
        lines.append(
            f"  {step}. Export environment variables above in your "
            f"shell profile"
        )
        step += 1
    lines.append(
        f"  {step}. Restart {_client_display_name(plan.client_name)}"
    )

    return "\n".join(lines)


def _client_display_name(client_name: str) -> str:
    """Human-readable client name."""
    return {
        "claude-desktop": "Claude Desktop",
        "claude-code": "Claude Code",
        "cursor": "Cursor",
        "windsurf": "Windsurf",
    }.get(client_name, client_name)


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def migrate_command(argv: list[str] | None = None) -> int:
    """Parse migrate subcommand args and run migration.

    Returns exit code (0 = success, 1 = error).
    """
    import argparse

    parser = argparse.ArgumentParser(
        prog="sanna-gateway migrate",
        description=(
            "Migrate an MCP client config to use sanna-gateway. "
            "Wraps existing MCP servers behind the enforcement proxy."
        ),
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--client",
        choices=sorted(_ADAPTERS.keys()),
        help="MCP client to migrate",
    )
    group.add_argument(
        "--auto",
        action="store_true",
        help="Auto-detect installed MCP clients",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would change without writing files",
    )
    parser.add_argument(
        "--template",
        choices=sorted(_GATEWAY_TEMPLATES.keys()),
        default=None,
        help=(
            "Constitution template (default: cowork-personal "
            "for Claude Desktop, claude-code-standard for others)"
        ),
    )
    parser.add_argument(
        "--sanna-dir",
        default=None,
        help="Sanna config directory (default: ~/.sanna)",
    )
    args = parser.parse_args(argv)

    sanna_dir = Path(args.sanna_dir) if args.sanna_dir else None

    if args.auto:
        return _run_auto_migrate(
            dry_run=args.dry_run,
            template=args.template,
            sanna_dir=sanna_dir,
        )
    else:
        return _run_single_migrate(
            client_name=args.client,
            dry_run=args.dry_run,
            template=args.template,
            sanna_dir=sanna_dir,
        )


def _run_single_migrate(
    client_name: str,
    dry_run: bool,
    template: str | None,
    sanna_dir: Path | None,
) -> int:
    """Migrate a single client. Returns exit code."""
    try:
        adapter = get_adapter(client_name)
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

    try:
        config_path = adapter.detect_config()
    except NotImplementedError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

    if config_path is None:
        expected = adapter.config_paths()
        locations = ", ".join(str(p) for p in expected) or "(unknown)"
        print(
            f"No {adapter.name} config found.\n"
            f"Expected location(s): {locations}",
            file=sys.stderr,
        )
        return 1

    try:
        plan = plan_migration(
            adapter=adapter,
            config_path=config_path,
            template=template,
            sanna_dir=sanna_dir,
        )
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(f"Error reading config: {e}", file=sys.stderr)
        return 1

    if not plan.migratable:
        print(format_plan(plan))
        return 0

    if dry_run:
        print("[DRY RUN] No files will be written.\n")
        print(format_plan(plan))
        return 0

    result = execute_migration(plan)
    print(format_plan(plan, result))

    if not result.success:
        return 1
    return 0


def _run_auto_migrate(
    dry_run: bool,
    template: str | None,
    sanna_dir: Path | None,
) -> int:
    """Auto-detect and migrate all installed clients."""
    found = detect_installed_clients()

    if not found:
        print(
            "No supported MCP clients detected.\n"
            "Supported clients: "
            + ", ".join(sorted(_ADAPTERS.keys())),
            file=sys.stderr,
        )
        return 1

    print(f"Detected {len(found)} MCP client(s):\n")

    exit_code = 0
    for client_name, config_path in found:
        print(f"--- {_client_display_name(client_name)} ---")
        code = _run_single_migrate(
            client_name=client_name,
            dry_run=dry_run,
            template=template,
            sanna_dir=sanna_dir,
        )
        if code != 0:
            exit_code = code
        print()

    return exit_code
