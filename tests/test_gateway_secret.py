"""Block E tests — gateway secret persistence + env var override."""

import os
import stat

import pytest

mcp = pytest.importorskip("mcp", reason="mcp extra not installed")

from sanna.gateway.server import SannaGateway


class TestGatewaySecret:
    def test_gateway_secret_persistence(self, tmp_path):
        """Create secret, verify same secret reloaded."""
        secret_path = str(tmp_path / "gateway_secret")

        # First load: creates the secret
        secret1 = SannaGateway._load_or_create_secret(secret_path)
        assert len(secret1) == 32
        assert os.path.exists(secret_path)

        # Second load: returns the same secret
        secret2 = SannaGateway._load_or_create_secret(secret_path)
        assert secret1 == secret2

    def test_gateway_secret_permissions(self, tmp_path):
        """File created with 0o600 (owner read/write only)."""
        secret_path = str(tmp_path / "gateway_secret")
        SannaGateway._load_or_create_secret(secret_path)

        file_stat = os.stat(secret_path)
        mode = stat.S_IMODE(file_stat.st_mode)
        assert mode == 0o600

    def test_gateway_secret_env_var(self, tmp_path, monkeypatch):
        """SANNA_GATEWAY_SECRET env var overrides file."""
        secret_hex = "aa" * 32  # 32 bytes as hex
        monkeypatch.setenv("SANNA_GATEWAY_SECRET", secret_hex)

        secret_path = str(tmp_path / "gateway_secret")
        result = SannaGateway._load_or_create_secret(secret_path)

        assert result == bytes.fromhex(secret_hex)
        # File should NOT be created when env var is used
        assert not os.path.exists(secret_path)

    def test_gateway_secret_invalid_env_var(self, tmp_path, monkeypatch):
        """Invalid hex env var is ignored, falls through to file."""
        monkeypatch.setenv("SANNA_GATEWAY_SECRET", "not-valid-hex")

        secret_path = str(tmp_path / "gateway_secret")
        result = SannaGateway._load_or_create_secret(secret_path)

        # Should have created a file instead
        assert len(result) == 32
        assert os.path.exists(secret_path)
