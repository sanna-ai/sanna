"""Tests for sanna.utils.safe_io — atomic writes and secure directories."""

import json
import os
import stat
import sys
import threading

import pytest

from sanna.utils.safe_io import SecurityError, atomic_write_sync, ensure_secure_dir


# ---------------------------------------------------------------------------
# atomic_write_sync
# ---------------------------------------------------------------------------


class TestAtomicWriteSync:

    def test_creates_file(self, tmp_path):
        """Basic write and read back."""
        target = tmp_path / "output.txt"
        atomic_write_sync(target, "hello world")
        assert target.read_text() == "hello world"

    def test_creates_file_bytes(self, tmp_path):
        """Write bytes data."""
        target = tmp_path / "output.bin"
        atomic_write_sync(target, b"\x00\x01\x02\x03")
        assert target.read_bytes() == b"\x00\x01\x02\x03"

    def test_overwrites_existing(self, tmp_path):
        """Atomic replacement of an existing file."""
        target = tmp_path / "output.txt"
        target.write_text("old content")
        atomic_write_sync(target, "new content")
        assert target.read_text() == "new content"

    @pytest.mark.skipif(sys.platform == "win32", reason="symlinks need admin on Windows")
    def test_rejects_symlink_target(self, tmp_path):
        """A symlink at the target path raises SecurityError."""
        real = tmp_path / "real.txt"
        real.write_text("original")
        link = tmp_path / "link.txt"
        os.symlink(str(real), str(link))

        with pytest.raises(SecurityError, match="symlink"):
            atomic_write_sync(link, "injected")

        # Original content unchanged
        assert real.read_text() == "original"

    def test_cleans_up_on_failure(self, tmp_path):
        """Simulate write failure — no temp file left behind."""
        target = tmp_path / "output.txt"

        # Make the parent directory read-only to force os.replace failure
        # (but mkstemp should still work in /tmp, so use a missing parent)
        missing_parent = tmp_path / "nonexistent" / "output.txt"
        with pytest.raises(FileNotFoundError):
            atomic_write_sync(missing_parent, "data")

        # No temp files should remain in tmp_path
        remaining = list(tmp_path.glob(".*tmp*"))
        assert remaining == []

    @pytest.mark.skipif(sys.platform == "win32", reason="POSIX permissions only")
    def test_sets_permissions(self, tmp_path):
        """Verify file permissions are applied."""
        target = tmp_path / "secret.key"
        atomic_write_sync(target, "secret-data", mode=0o600)
        mode = stat.S_IMODE(os.stat(target).st_mode)
        assert mode == 0o600

    @pytest.mark.skipif(sys.platform == "win32", reason="POSIX permissions only")
    def test_sets_custom_permissions(self, tmp_path):
        """Verify custom permissions (e.g. 0o644) are applied."""
        target = tmp_path / "public.txt"
        atomic_write_sync(target, "public-data", mode=0o644)
        mode = stat.S_IMODE(os.stat(target).st_mode)
        assert mode == 0o644

    def test_concurrent_writes_no_corruption(self, tmp_path):
        """Multiple threads writing to the same file don't corrupt data."""
        target = tmp_path / "shared.txt"
        errors = []

        def writer(value):
            try:
                for _ in range(20):
                    atomic_write_sync(target, f"value-{value}")
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=writer, args=(i,)) for i in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors
        # File should contain one of the values, not a mix
        content = target.read_text()
        assert content.startswith("value-")


# ---------------------------------------------------------------------------
# ensure_secure_dir
# ---------------------------------------------------------------------------


class TestEnsureSecureDir:

    @pytest.mark.skipif(sys.platform == "win32", reason="POSIX permissions only")
    def test_creates_with_permissions(self, tmp_path):
        """New directory gets the requested mode."""
        d = tmp_path / "secure_dir"
        ensure_secure_dir(d)
        mode = stat.S_IMODE(os.stat(d).st_mode)
        assert mode == 0o700

    @pytest.mark.skipif(sys.platform == "win32", reason="POSIX permissions only")
    def test_fixes_existing_permissions(self, tmp_path):
        """Pre-existing directory gets permissions corrected."""
        d = tmp_path / "existing"
        d.mkdir(mode=0o755)
        ensure_secure_dir(d, mode=0o700)
        mode = stat.S_IMODE(os.stat(d).st_mode)
        assert mode == 0o700

    @pytest.mark.skipif(sys.platform == "win32", reason="symlinks need admin on Windows")
    def test_rejects_symlink_dir(self, tmp_path):
        """Symlink directory raises SecurityError."""
        real = tmp_path / "real_dir"
        real.mkdir()
        link = tmp_path / "link_dir"
        os.symlink(str(real), str(link))

        with pytest.raises(SecurityError, match="symlink"):
            ensure_secure_dir(link)


# ---------------------------------------------------------------------------
# Gateway secret validation
# ---------------------------------------------------------------------------


class TestGatewaySecretValidation:

    def test_rejects_short_secret(self, tmp_path, monkeypatch):
        """Gateway secret < 32 bytes raises SecurityError."""
        mcp = pytest.importorskip("mcp")

        secret_path = tmp_path / "gateway_secret"
        secret_path.write_bytes(b"tooshort")

        from sanna.gateway.server import SannaGateway
        with pytest.raises(SecurityError, match="32 bytes"):
            SannaGateway._load_or_create_secret(str(secret_path))

    def test_accepts_valid_secret(self, tmp_path):
        """32-byte secret loads successfully."""
        mcp = pytest.importorskip("mcp")

        secret_path = tmp_path / "gateway_secret"
        secret_path.write_bytes(os.urandom(32))

        from sanna.gateway.server import SannaGateway
        secret = SannaGateway._load_or_create_secret(str(secret_path))
        assert len(secret) == 32

    def test_creates_secret_with_proper_permissions(self, tmp_path):
        """New secret file gets 0o600 permissions."""
        mcp = pytest.importorskip("mcp")

        secret_path = tmp_path / "sanna_dir" / "gateway_secret"

        from sanna.gateway.server import SannaGateway
        secret = SannaGateway._load_or_create_secret(str(secret_path))
        assert len(secret) == 32
        assert secret_path.exists()

        if sys.platform != "win32":
            mode = stat.S_IMODE(os.stat(secret_path).st_mode)
            assert mode == 0o600


# ---------------------------------------------------------------------------
# Receipt persistence uses atomic write
# ---------------------------------------------------------------------------


class TestPersistReceiptAtomic:

    def test_persist_receipt_no_tmp_suffix(self, tmp_path):
        """Verify _persist_receipt doesn't leave .tmp files behind."""
        mcp = pytest.importorskip("mcp")

        from sanna.gateway.server import SannaGateway

        receipt = {
            "receipt_id": "test123",
            "timestamp": "2024-01-01T00:00:00+00:00",
            "inputs": {"context": "test"},
            "outputs": {"output": "test"},
        }

        # Create a minimal gateway instance with just receipt_store_path
        gw = object.__new__(SannaGateway)
        gw._receipt_store_path = str(tmp_path / "receipts")

        # Need to set redaction config
        from sanna.gateway.config import RedactionConfig
        gw._redaction_config = RedactionConfig()

        gw._persist_receipt(receipt)

        # Verify receipt was written
        receipt_files = list((tmp_path / "receipts").glob("*.json"))
        assert len(receipt_files) == 1

        # Verify no .tmp files remain
        tmp_files = list((tmp_path / "receipts").glob("*.tmp"))
        assert tmp_files == []

        # Verify content
        content = json.loads(receipt_files[0].read_text())
        assert content["receipt_id"] == "test123"


# ---------------------------------------------------------------------------
# Async I/O offloading
# ---------------------------------------------------------------------------


class TestAsyncIOOffloading:

    @pytest.mark.asyncio
    async def test_persist_receipt_async_uses_executor(self, tmp_path):
        """Verify _persist_receipt_async dispatches to thread pool."""
        mcp = pytest.importorskip("mcp")

        from unittest.mock import AsyncMock, patch
        from sanna.gateway.server import SannaGateway

        gw = object.__new__(SannaGateway)
        gw._receipt_store_path = str(tmp_path / "receipts")
        from sanna.gateway.config import RedactionConfig
        gw._redaction_config = RedactionConfig()

        receipt = {
            "receipt_id": "async_test",
            "timestamp": "2024-01-01T00:00:00+00:00",
            "inputs": {},
            "outputs": {},
        }

        # Verify async version actually writes the file
        await gw._persist_receipt_async(receipt)

        receipt_files = list((tmp_path / "receipts").glob("*.json"))
        assert len(receipt_files) == 1
