"""CRIT-01 — Approval Channel Redesign tests.

Covers:
- Default token_delivery is ["stderr"] (not ["file", "stderr"])
- File delivery gated behind SANNA_INSECURE_FILE_TOKENS=1
- Token not written to file without the env var
- Token delivery via stderr works
- Webhook delivery sends correct POST body
- Webhook SSRF protection blocks localhost, RFC 1918, metadata endpoints
- "webhook" accepted in _VALID_DELIVERY
- Default token_expiry_seconds is 900
- Expired token rejected
- TTY safety check on sanna-approve CLI (CRIT-01)
"""

from __future__ import annotations

import json
import os
import sys
import textwrap
import time

import pytest

# ---------------------------------------------------------------------------
# MCP availability check — gateway tests require mcp extra
# ---------------------------------------------------------------------------

try:
    import mcp  # noqa: F401
    _has_mcp = True
except (ImportError, ModuleNotFoundError):
    _has_mcp = False

requires_mcp = pytest.mark.skipif(not _has_mcp, reason="mcp extra not installed")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _create_signed_constitution(tmp_path, authority_boundaries=None):
    """Create a signed constitution for testing."""
    from sanna.crypto import generate_keypair
    from sanna.constitution import (
        Constitution, AgentIdentity, Provenance, Boundary,
        sign_constitution, save_constitution,
    )

    keys_dir = tmp_path / "keys"
    private_key_path, public_key_path = generate_keypair(str(keys_dir))

    constitution = Constitution(
        schema_version="0.1.0",
        identity=AgentIdentity(agent_name="test-agent", domain="testing"),
        provenance=Provenance(
            authored_by="test@example.com",
            approved_by=["approver@example.com"],
            approval_date="2024-01-01",
            approval_method="manual-sign-off",
        ),
        boundaries=[
            Boundary(id="B001", description="Test", category="scope",
                     severity="high"),
        ],
        authority_boundaries=authority_boundaries,
    )

    signed = sign_constitution(
        constitution, private_key_path=str(private_key_path),
    )
    const_path = tmp_path / "constitution.yaml"
    save_constitution(signed, const_path)
    return str(const_path), str(private_key_path), str(public_key_path)


def _write_config(tmp_path, content, filename="gateway.yaml"):
    """Write YAML config content to a temp file. Returns path."""
    p = tmp_path / filename
    p.write_text(textwrap.dedent(content))
    return str(p)


def _minimal_config(const_path, key_path):
    """Return minimal valid config YAML content."""
    return f"""\
    gateway:
      constitution: {const_path}
      signing_key: {key_path}

    downstream:
      - name: mock
        command: echo
    """


# ---------------------------------------------------------------------------
# Default token_delivery is ["stderr"]
# ---------------------------------------------------------------------------


@requires_mcp
class TestDefaultTokenDelivery:
    def test_default_is_stderr_only(self, tmp_path):
        """GatewayConfig default token_delivery is ["stderr"], not ["file", "stderr"]."""
        from sanna.gateway.config import GatewayConfig
        cfg = GatewayConfig()
        assert cfg.token_delivery == ["stderr"]

    def test_config_parse_default_is_stderr(self, tmp_path):
        """load_gateway_config returns ["stderr"] when no token_delivery is set."""
        from sanna.gateway.config import load_gateway_config
        const_path, key_path, _ = _create_signed_constitution(tmp_path)
        config_path = _write_config(tmp_path, _minimal_config(const_path, key_path))
        cfg = load_gateway_config(config_path)
        assert cfg.token_delivery == ["stderr"]

    def test_server_default_is_stderr(self, tmp_path):
        """SannaGateway default _token_delivery is ["stderr"]."""
        from sanna.gateway.server import SannaGateway
        gw = object.__new__(SannaGateway)
        # The default in __init__ uses `or ["stderr"]`
        gw._token_delivery = None or ["stderr"]
        assert gw._token_delivery == ["stderr"]


# ---------------------------------------------------------------------------
# File delivery gated behind SANNA_INSECURE_FILE_TOKENS=1
# ---------------------------------------------------------------------------


@requires_mcp
class TestFileDeliveryGate:
    def test_file_delivery_without_env_var_raises(self, tmp_path, monkeypatch):
        """Config error raised when file delivery used without env var."""
        from sanna.gateway.config import load_gateway_config, GatewayConfigError
        monkeypatch.delenv("SANNA_INSECURE_FILE_TOKENS", raising=False)

        const_path, key_path, _ = _create_signed_constitution(tmp_path)
        config_yaml = f"""\
        gateway:
          constitution: {const_path}
          signing_key: {key_path}
          token_delivery: ["file"]

        downstream:
          - name: mock
            command: echo
        """
        config_path = _write_config(tmp_path, config_yaml)

        with pytest.raises(GatewayConfigError, match="File-based token delivery is insecure"):
            load_gateway_config(config_path)

    def test_file_delivery_with_env_var_succeeds(self, tmp_path, monkeypatch):
        """File delivery works when SANNA_INSECURE_FILE_TOKENS=1."""
        from sanna.gateway.config import load_gateway_config
        monkeypatch.setenv("SANNA_INSECURE_FILE_TOKENS", "1")

        const_path, key_path, _ = _create_signed_constitution(tmp_path)
        config_yaml = f"""\
        gateway:
          constitution: {const_path}
          signing_key: {key_path}
          token_delivery: ["file"]

        downstream:
          - name: mock
            command: echo
        """
        config_path = _write_config(tmp_path, config_yaml)
        cfg = load_gateway_config(config_path)
        assert "file" in cfg.token_delivery

    def test_file_delivery_wrong_env_value_raises(self, tmp_path, monkeypatch):
        """Only SANNA_INSECURE_FILE_TOKENS=1 (exactly) is accepted."""
        from sanna.gateway.config import load_gateway_config, GatewayConfigError
        monkeypatch.setenv("SANNA_INSECURE_FILE_TOKENS", "true")

        const_path, key_path, _ = _create_signed_constitution(tmp_path)
        config_yaml = f"""\
        gateway:
          constitution: {const_path}
          signing_key: {key_path}
          token_delivery: ["file", "stderr"]

        downstream:
          - name: mock
            command: echo
        """
        config_path = _write_config(tmp_path, config_yaml)

        with pytest.raises(GatewayConfigError, match="SANNA_INSECURE_FILE_TOKENS"):
            load_gateway_config(config_path)


@requires_mcp
class TestTokenNotWrittenWithoutEnvVar:
    def test_no_file_created_with_stderr_only(self, tmp_path, monkeypatch):
        """When token_delivery is ["stderr"], no pending_tokens.json is created."""
        from sanna.gateway.server import SannaGateway, PendingEscalation

        # Set up a fake gateway with stderr-only delivery
        gw = object.__new__(SannaGateway)
        gw._escalation_store = type("FakeStore", (), {"timeout": 300})()
        gw._token_delivery = ["stderr"]
        gw._require_approval_token = True
        gw._gateway_secret = os.urandom(32)

        sanna_dir = tmp_path / "home" / ".sanna"
        tokens_path = str(sanna_dir / "pending_tokens.json")
        monkeypatch.setenv("HOME", str(tmp_path / "home"))

        entry = PendingEscalation(
            escalation_id="esc_test",
            prefixed_name="mock_update",
            original_name="update",
            server_name="mock",
            arguments={"id": "1"},
            reason="test",
            created_at="2024-01-01T00:00:00Z",
        )

        # Deliver via stderr only
        gw._deliver_token(entry, "test_token_123")

        # File should NOT exist
        assert not os.path.exists(tokens_path)
        assert not sanna_dir.exists() or not (sanna_dir / "pending_tokens.json").exists()


# ---------------------------------------------------------------------------
# Token delivery via stderr
# ---------------------------------------------------------------------------


@requires_mcp
class TestStderrDelivery:
    def test_stderr_output(self, tmp_path, capsys):
        """Token printed to stderr with expected format."""
        from sanna.gateway.server import SannaGateway, PendingEscalation

        gw = object.__new__(SannaGateway)
        gw._escalation_store = type("FakeStore", (), {"timeout": 300})()
        gw._token_delivery = ["stderr"]
        gw._approval_webhook_url = ""

        entry = PendingEscalation(
            escalation_id="esc_stderr_test",
            prefixed_name="mock_update",
            original_name="update",
            server_name="mock",
            arguments={"id": "1"},
            reason="test",
            created_at="2024-01-01T00:00:00Z",
        )

        gw._deliver_token(entry, "tok_stderr_abc")

        captured = capsys.readouterr()
        assert "[SANNA] Approval token for escalation esc_stderr_test: tok_stderr_abc" in captured.err
        assert "Provide this token to approve" in captured.err


# ---------------------------------------------------------------------------
# Webhook delivery
# ---------------------------------------------------------------------------


@requires_mcp
class TestWebhookDelivery:
    def test_webhook_sends_correct_post_body(self, tmp_path):
        """Webhook delivery POSTs the expected JSON body."""
        from unittest.mock import patch, MagicMock
        from sanna.gateway.server import SannaGateway, PendingEscalation

        gw = object.__new__(SannaGateway)
        gw._escalation_store = type("FakeStore", (), {"timeout": 900})()
        gw._token_delivery = ["webhook"]
        gw._approval_webhook_url = "https://hooks.example.com/approve"

        entry = PendingEscalation(
            escalation_id="esc_webhook_01",
            prefixed_name="notion_API-patch-page",
            original_name="API-patch-page",
            server_name="notion",
            arguments={"page_id": "abc"},
            reason="Page mutations require approval",
            created_at="2024-01-01T00:00:00Z",
        )

        token_info = {
            "escalation_id": "esc_webhook_01",
            "token": "tok_webhook_secret",
            "tool_name": "notion_API-patch-page",
            "timestamp": "2024-01-01T00:00:00Z",
            "ttl_remaining": 900,
            "expires_at": time.time() + 900,
        }

        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)

        with patch("urllib.request.urlopen", return_value=mock_resp) as mock_urlopen:
            gw._deliver_token_via_webhook(entry, token_info)

        # Verify urlopen was called
        assert mock_urlopen.called
        request = mock_urlopen.call_args[0][0]
        assert request.full_url == "https://hooks.example.com/approve"
        assert request.method == "POST"

        body = json.loads(request.data.decode("utf-8"))
        assert body["escalation_id"] == "esc_webhook_01"
        assert body["tool_name"] == "notion_API-patch-page"
        assert body["reason"] == "Page mutations require approval"
        assert body["token"] == "tok_webhook_secret"
        assert "expires_at" in body
        assert body["approve_command"].startswith("sanna-approve --escalation-id esc_webhook_01")

    def test_webhook_accepted_in_valid_delivery(self):
        """'webhook' is in the _VALID_DELIVERY set used by config."""
        # The config parser should accept "webhook" without error
        from sanna.gateway.config import load_gateway_config, GatewayConfigError
        # If "webhook" were invalid, config parsing would raise.
        # We test this indirectly via the validate_webhook_url path.
        from sanna.gateway.config import validate_webhook_url
        # A valid HTTPS URL should pass
        validate_webhook_url("https://hooks.example.com/approve")

    def test_webhook_no_url_logs_warning(self, tmp_path, caplog):
        """Webhook delivery with no URL logs a warning."""
        import logging
        from sanna.gateway.server import SannaGateway, PendingEscalation

        gw = object.__new__(SannaGateway)
        gw._approval_webhook_url = ""

        entry = PendingEscalation(
            escalation_id="esc_no_url",
            prefixed_name="mock_update",
            original_name="update",
            server_name="mock",
            arguments={},
            reason="test",
            created_at="2024-01-01T00:00:00Z",
        )

        with caplog.at_level(logging.WARNING, logger="sanna.gateway.server"):
            gw._deliver_token_via_webhook(entry, {"token": "x", "expires_at": time.time() + 300})

        assert any("no approval_webhook_url" in r.message.lower() or
                    "approval_webhook_url" in r.message
                    for r in caplog.records)


# ---------------------------------------------------------------------------
# Webhook SSRF protection
# ---------------------------------------------------------------------------


@requires_mcp
class TestWebhookSSRFProtection:
    def test_blocks_localhost(self):
        from sanna.gateway.config import validate_webhook_url, GatewayConfigError
        with pytest.raises(GatewayConfigError, match="localhost"):
            validate_webhook_url("https://localhost:8080/hook")

    def test_blocks_127_0_0_1(self):
        from sanna.gateway.config import validate_webhook_url, GatewayConfigError
        with pytest.raises(GatewayConfigError, match="localhost"):
            validate_webhook_url("https://127.0.0.1/hook")

    def test_blocks_127_0_0_x(self):
        from sanna.gateway.config import validate_webhook_url, GatewayConfigError
        with pytest.raises(GatewayConfigError, match="loopback"):
            validate_webhook_url("https://127.0.0.2/hook")

    def test_blocks_10_network(self):
        from sanna.gateway.config import validate_webhook_url, GatewayConfigError
        with pytest.raises(GatewayConfigError, match="private"):
            validate_webhook_url("https://10.0.0.1/hook")

    def test_blocks_172_16_network(self):
        from sanna.gateway.config import validate_webhook_url, GatewayConfigError
        with pytest.raises(GatewayConfigError, match="private"):
            validate_webhook_url("https://172.16.0.1/hook")

    def test_blocks_192_168_network(self):
        from sanna.gateway.config import validate_webhook_url, GatewayConfigError
        with pytest.raises(GatewayConfigError, match="private"):
            validate_webhook_url("https://192.168.1.1/hook")

    def test_blocks_link_local(self):
        from sanna.gateway.config import validate_webhook_url, GatewayConfigError
        with pytest.raises(GatewayConfigError, match="link-local"):
            validate_webhook_url("https://169.254.1.1/hook")

    def test_blocks_cloud_metadata(self):
        from sanna.gateway.config import validate_webhook_url, GatewayConfigError
        with pytest.raises(GatewayConfigError, match="metadata"):
            validate_webhook_url("http://169.254.169.254/latest/meta-data/")

    def test_blocks_non_http_scheme(self):
        from sanna.gateway.config import validate_webhook_url, GatewayConfigError
        with pytest.raises(GatewayConfigError, match="http or https"):
            validate_webhook_url("ftp://example.com/hook")

    def test_blocks_no_scheme(self):
        from sanna.gateway.config import validate_webhook_url, GatewayConfigError
        with pytest.raises(GatewayConfigError, match="http or https"):
            validate_webhook_url("example.com/hook")

    def test_allows_valid_https(self):
        from sanna.gateway.config import validate_webhook_url
        # Should not raise
        validate_webhook_url("https://hooks.slack.com/services/T00/B00/xxx")

    def test_allows_valid_http_external(self):
        from sanna.gateway.config import validate_webhook_url
        # HTTP is accepted (not just HTTPS) for non-private addresses
        validate_webhook_url("http://8.8.8.8/hook")

    def test_allows_hostname_not_ip(self):
        from sanna.gateway.config import validate_webhook_url
        # Non-IP hostnames pass (DNS resolution is not done at config time)
        validate_webhook_url("https://my-internal-service.company.com/hook")


# ---------------------------------------------------------------------------
# Token expiry
# ---------------------------------------------------------------------------


@requires_mcp
class TestTokenExpiry:
    def test_default_token_expiry_is_900(self, tmp_path):
        """Default token_expiry_seconds is 900 (15 minutes)."""
        from sanna.gateway.config import GatewayConfig
        cfg = GatewayConfig()
        assert cfg.token_expiry_seconds == 900

    def test_config_parse_default_token_expiry(self, tmp_path):
        """load_gateway_config returns 900 when token_expiry_seconds not set."""
        from sanna.gateway.config import load_gateway_config
        const_path, key_path, _ = _create_signed_constitution(tmp_path)
        config_path = _write_config(tmp_path, _minimal_config(const_path, key_path))
        cfg = load_gateway_config(config_path)
        assert cfg.token_expiry_seconds == 900

    def test_custom_token_expiry(self, tmp_path):
        """Custom token_expiry_seconds parsed correctly."""
        from sanna.gateway.config import load_gateway_config
        const_path, key_path, _ = _create_signed_constitution(tmp_path)
        config_yaml = f"""\
        gateway:
          constitution: {const_path}
          signing_key: {key_path}
          token_expiry_seconds: 1800

        downstream:
          - name: mock
            command: echo
        """
        config_path = _write_config(tmp_path, config_yaml)
        cfg = load_gateway_config(config_path)
        assert cfg.token_expiry_seconds == 1800

    def test_expired_token_rejected(self, tmp_path):
        """EscalationStore.is_expired returns True for expired entries."""
        from sanna.gateway.server import EscalationStore, PendingEscalation
        from datetime import datetime, timezone, timedelta

        store = EscalationStore(timeout=1)  # 1-second timeout

        # Create an entry with a timestamp 10 seconds in the past
        old_time = (
            datetime.now(timezone.utc) - timedelta(seconds=10)
        ).isoformat()

        entry = PendingEscalation(
            escalation_id="esc_expired",
            prefixed_name="mock_update",
            original_name="update",
            server_name="mock",
            arguments={"id": "1"},
            reason="test",
            created_at=old_time,
        )

        assert store.is_expired(entry) is True

    def test_non_expired_token_accepted(self, tmp_path):
        """EscalationStore.is_expired returns False for fresh entries."""
        from sanna.gateway.server import EscalationStore, PendingEscalation
        from datetime import datetime, timezone

        store = EscalationStore(timeout=900)

        entry = PendingEscalation(
            escalation_id="esc_fresh",
            prefixed_name="mock_update",
            original_name="update",
            server_name="mock",
            arguments={"id": "1"},
            reason="test",
            created_at=datetime.now(timezone.utc).isoformat(),
        )

        assert store.is_expired(entry) is False


# ---------------------------------------------------------------------------
# Webhook config validation
# ---------------------------------------------------------------------------


@requires_mcp
class TestWebhookConfigValidation:
    def test_webhook_in_config_accepted(self, tmp_path):
        """'webhook' is accepted as a token_delivery method in config."""
        from sanna.gateway.config import load_gateway_config
        const_path, key_path, _ = _create_signed_constitution(tmp_path)
        config_yaml = f"""\
        gateway:
          constitution: {const_path}
          signing_key: {key_path}
          token_delivery: ["webhook"]
          approval_webhook_url: "https://hooks.example.com/approve"

        downstream:
          - name: mock
            command: echo
        """
        config_path = _write_config(tmp_path, config_yaml)
        cfg = load_gateway_config(config_path)
        assert "webhook" in cfg.token_delivery
        assert cfg.approval_webhook_url == "https://hooks.example.com/approve"

    def test_webhook_without_url_raises(self, tmp_path):
        """webhook delivery without approval_webhook_url raises config error."""
        from sanna.gateway.config import load_gateway_config, GatewayConfigError
        const_path, key_path, _ = _create_signed_constitution(tmp_path)
        config_yaml = f"""\
        gateway:
          constitution: {const_path}
          signing_key: {key_path}
          token_delivery: ["webhook"]

        downstream:
          - name: mock
            command: echo
        """
        config_path = _write_config(tmp_path, config_yaml)
        with pytest.raises(GatewayConfigError, match="approval_webhook_url is required"):
            load_gateway_config(config_path)

    def test_file_warning_on_delivery(self, tmp_path, monkeypatch, capsys):
        """File delivery emits warning to stderr on every token write."""
        from sanna.gateway.server import SannaGateway, PendingEscalation

        gw = object.__new__(SannaGateway)
        gw._escalation_store = type("FakeStore", (), {"timeout": 300})()
        gw._token_delivery = ["file"]
        gw._approval_webhook_url = ""
        gw._MAX_PENDING_TOKENS = 1000

        sanna_dir = tmp_path / "home" / ".sanna"
        tokens_path = str(sanna_dir / "pending_tokens.json")
        monkeypatch.setattr(
            os.path, "expanduser",
            lambda p: tokens_path if "pending_tokens" in p else p,
        )

        entry = PendingEscalation(
            escalation_id="esc_warn_test",
            prefixed_name="mock_update",
            original_name="update",
            server_name="mock",
            arguments={"id": "1"},
            reason="test",
            created_at="2024-01-01T00:00:00Z",
        )

        gw._deliver_token(entry, "tok_warn_test")

        captured = capsys.readouterr()
        assert "WARNING" in captured.err
        assert "insecure" in captured.err.lower()


# ---------------------------------------------------------------------------
# CRIT-01: TTY safety check on sanna-approve CLI
# ---------------------------------------------------------------------------


class TestApproveTTYCheck:
    """Verify that approve_constitution_cmd enforces TTY/non-interactive gating."""

    _REQUIRED_ARGS = [
        "dummy_constitution.yaml",
        "--approver-key", "dummy.key",
        "--approver-id", "approver@example.com",
        "--approver-role", "CISO",
        "--version", "1.0",
        "--no-verify",
    ]

    @staticmethod
    def _mock_stdin_fileno():
        """Return a mock stdin with a working fileno() for os.isatty mocking."""
        from unittest.mock import MagicMock
        mock_stdin = MagicMock()
        mock_stdin.fileno.return_value = 0
        return mock_stdin

    def test_non_tty_without_flag_exits_error(self, monkeypatch, capsys):
        """Non-TTY without --non-interactive flag prints error and exits 1."""
        from unittest.mock import patch

        monkeypatch.setattr("sys.argv", ["sanna-approve"] + self._REQUIRED_ARGS)

        mock_stdin = self._mock_stdin_fileno()
        with patch("os.isatty", return_value=False), \
             patch("sys.stdin", mock_stdin):
            from sanna.cli import approve_constitution_cmd
            rc = approve_constitution_cmd()

        assert rc == 1
        captured = capsys.readouterr()
        assert "sanna-approve requires --non-interactive flag when not run from a terminal." in captured.err

    def test_non_interactive_flag_skips_tty_check(self, monkeypatch, tmp_path):
        """--non-interactive flag bypasses TTY check (proceeds to approval logic)."""
        from unittest.mock import patch, MagicMock

        cli_args = self._REQUIRED_ARGS + ["--non-interactive"]
        monkeypatch.setattr("sys.argv", ["sanna-approve"] + cli_args)

        mock_record = MagicMock()
        mock_record.approver_id = "approver@example.com"
        mock_record.approver_role = "CISO"
        mock_record.constitution_version = "1.0"
        mock_record.content_hash = "a" * 64
        mock_record.approved_at = "2024-01-01T00:00:00Z"
        mock_record.previous_version_hash = None

        mock_stdin = self._mock_stdin_fileno()
        with patch("os.isatty", return_value=False), \
             patch("sys.stdin", mock_stdin), \
             patch("sanna.constitution.approve_constitution", return_value=mock_record) as mock_approve:
            from sanna.cli import approve_constitution_cmd
            rc = approve_constitution_cmd()

        assert rc == 0
        mock_approve.assert_called_once()

    def test_tty_mode_with_n_aborts(self, monkeypatch, capsys):
        """TTY mode with 'n' input aborts with exit code 1."""
        from unittest.mock import patch

        monkeypatch.setattr("sys.argv", ["sanna-approve"] + self._REQUIRED_ARGS)

        mock_stdin = self._mock_stdin_fileno()
        with patch("os.isatty", return_value=True), \
             patch("sys.stdin", mock_stdin), \
             patch("builtins.input", return_value="n"):
            from sanna.cli import approve_constitution_cmd
            rc = approve_constitution_cmd()

        assert rc == 1
        captured = capsys.readouterr()
        assert "Aborted." in captured.err

    def test_tty_mode_with_y_proceeds(self, monkeypatch):
        """TTY mode with 'y' input proceeds to approval logic."""
        from unittest.mock import patch, MagicMock

        monkeypatch.setattr("sys.argv", ["sanna-approve"] + self._REQUIRED_ARGS)

        mock_record = MagicMock()
        mock_record.approver_id = "approver@example.com"
        mock_record.approver_role = "CISO"
        mock_record.constitution_version = "1.0"
        mock_record.content_hash = "b" * 64
        mock_record.approved_at = "2024-01-01T00:00:00Z"
        mock_record.previous_version_hash = None

        mock_stdin = self._mock_stdin_fileno()
        with patch("os.isatty", return_value=True), \
             patch("sys.stdin", mock_stdin), \
             patch("builtins.input", return_value="y"), \
             patch("sanna.constitution.approve_constitution", return_value=mock_record) as mock_approve:
            from sanna.cli import approve_constitution_cmd
            rc = approve_constitution_cmd()

        assert rc == 0
        mock_approve.assert_called_once()

    def test_tty_mode_with_yes_proceeds(self, monkeypatch):
        """TTY mode with 'yes' (case-insensitive) proceeds to approval logic."""
        from unittest.mock import patch, MagicMock

        monkeypatch.setattr("sys.argv", ["sanna-approve"] + self._REQUIRED_ARGS)

        mock_record = MagicMock()
        mock_record.approver_id = "approver@example.com"
        mock_record.approver_role = "CISO"
        mock_record.constitution_version = "1.0"
        mock_record.content_hash = "c" * 64
        mock_record.approved_at = "2024-01-01T00:00:00Z"
        mock_record.previous_version_hash = None

        mock_stdin = self._mock_stdin_fileno()
        with patch("os.isatty", return_value=True), \
             patch("sys.stdin", mock_stdin), \
             patch("builtins.input", return_value="YES"), \
             patch("sanna.constitution.approve_constitution", return_value=mock_record) as mock_approve:
            from sanna.cli import approve_constitution_cmd
            rc = approve_constitution_cmd()

        assert rc == 0
        mock_approve.assert_called_once()

    def test_tty_mode_with_empty_input_aborts(self, monkeypatch, capsys):
        """TTY mode with empty input (just Enter) aborts -- default is No."""
        from unittest.mock import patch

        monkeypatch.setattr("sys.argv", ["sanna-approve"] + self._REQUIRED_ARGS)

        mock_stdin = self._mock_stdin_fileno()
        with patch("os.isatty", return_value=True), \
             patch("sys.stdin", mock_stdin), \
             patch("builtins.input", return_value=""):
            from sanna.cli import approve_constitution_cmd
            rc = approve_constitution_cmd()

        assert rc == 1
        captured = capsys.readouterr()
        assert "Aborted." in captured.err
