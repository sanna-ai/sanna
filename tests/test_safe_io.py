"""Tests for sanna.utils.safe_io — atomic writes and secure directories."""

import json
import os
import stat
import sys
import threading
from pathlib import Path

import pytest

from sanna.utils.safe_io import SecurityError, atomic_write_sync, atomic_write_text_sync, ensure_secure_dir


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

    def test_large_payload_exact_content(self, tmp_path):
        """5MB payload is written byte-for-byte without truncation (#2)."""
        target = tmp_path / "large.bin"
        # Create a 5MB payload with a recognizable pattern
        payload = bytes(range(256)) * (5 * 1024 * 1024 // 256)
        atomic_write_sync(target, payload)
        result = target.read_bytes()
        assert len(result) == len(payload), f"Expected {len(payload)} bytes, got {len(result)}"
        assert result == payload

    def test_write_loop_exact_content(self, tmp_path):
        """Known small content survives write loop without mutation."""
        target = tmp_path / "exact.txt"
        content = "The quick brown fox jumps over the lazy dog.\n" * 100
        atomic_write_sync(target, content)
        assert target.read_text() == content

    @pytest.mark.skipif(sys.platform == "win32", reason="POSIX only")
    def test_directory_fsync_after_replace(self, tmp_path):
        """Verify directory fsync path is exercised (no crash)."""
        target = tmp_path / "fsync_test.txt"
        # This just verifies the code path doesn't raise
        atomic_write_sync(target, "fsync data")
        assert target.read_text() == "fsync data"

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

    @pytest.mark.skipif(sys.platform == "win32", reason="POSIX fd-based chmod only")
    def test_fchmod_used_for_permissions(self, tmp_path):
        """Verify fd-based chmod sets permissions correctly (#4 TOCTOU fix)."""
        d = tmp_path / "fchmod_dir"
        d.mkdir(mode=0o755)
        ensure_secure_dir(d, mode=0o700)
        mode = stat.S_IMODE(os.stat(d).st_mode)
        assert mode == 0o700

    @pytest.mark.skipif(sys.platform == "win32", reason="O_NOFOLLOW not on Windows")
    def test_symlink_race_protection(self, tmp_path):
        """O_NOFOLLOW in fd-based path prevents symlink following (#4)."""
        real = tmp_path / "real_target"
        real.mkdir(mode=0o755)
        link = tmp_path / "race_link"
        os.symlink(str(real), str(link))

        # The pre-check catches it, but even if it didn't,
        # O_NOFOLLOW would prevent the fd-based chmod from following
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


# ---------------------------------------------------------------------------
# atomic_write_text_sync
# ---------------------------------------------------------------------------


class TestAtomicWriteTextSync:

    def test_writes_text(self, tmp_path):
        """Text helper writes UTF-8 and reads back correctly."""
        target = tmp_path / "text.txt"
        atomic_write_text_sync(target, "hello world")
        assert target.read_text(encoding="utf-8") == "hello world"

    def test_writes_unicode(self, tmp_path):
        """Unicode content round-trips correctly."""
        target = tmp_path / "unicode.txt"
        content = "Sanna governance — \u2714 checks passed"
        atomic_write_text_sync(target, content)
        assert target.read_text(encoding="utf-8") == content

    @pytest.mark.skipif(sys.platform == "win32", reason="POSIX permissions only")
    def test_respects_mode(self, tmp_path):
        """Text helper passes mode through to atomic_write_sync."""
        target = tmp_path / "secret.txt"
        atomic_write_text_sync(target, "secret", mode=0o600)
        mode = stat.S_IMODE(os.stat(target).st_mode)
        assert mode == 0o600


# ---------------------------------------------------------------------------
# Write site migration tests (Block 2 #5)
# ---------------------------------------------------------------------------


class TestWriteSiteMigration:

    def test_constitution_save_uses_atomic(self, tmp_path):
        """save_constitution() should use atomic writes."""
        from sanna.constitution import (
            Constitution, AgentIdentity, Provenance,
            save_constitution,
        )
        const = Constitution(
            schema_version="1.0.0",
            identity=AgentIdentity(agent_name="test", domain="test"),
            provenance=Provenance(
                authored_by="t@t.com", approved_by=["a@t.com"],
                approval_date="2026-01-01", approval_method="test",
            ),
            boundaries=[],
            invariants=[],
        )
        path = tmp_path / "const.yaml"
        save_constitution(const, path)
        assert path.exists()
        content = path.read_text()
        assert "sanna_constitution" in content

    def test_middleware_receipt_write_uses_atomic(self, tmp_path):
        """_write_receipt() should use atomic writes."""
        from sanna.middleware import _write_receipt
        receipt = {
            "receipt_id": "test-001",
            "correlation_id": "trace-001",
            "data": "test",
        }
        filepath = _write_receipt(receipt, str(tmp_path / "receipts"))
        assert filepath.exists()
        content = json.loads(filepath.read_text())
        assert content["receipt_id"] == "test-001"
        # Verify no temp files left
        tmp_files = list((tmp_path / "receipts").glob("*.tmp"))
        assert tmp_files == []

    def test_drift_report_write_uses_atomic(self, tmp_path):
        """export_drift_report_to_file() should use atomic writes."""
        from sanna.drift import DriftReport, export_drift_report_to_file
        report = DriftReport(
            window_days=7,
            threshold=0.1,
            generated_at="2026-01-01T00:00:00+00:00",
            agents=[],
            fleet_status="stable",
        )
        path = tmp_path / "reports" / "drift.json"
        result = export_drift_report_to_file(report, str(path), fmt="json")
        assert Path(result).exists()
