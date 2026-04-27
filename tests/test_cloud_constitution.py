"""Tests for the Cloud constitution fetch client (SAN-215)."""

from __future__ import annotations

import json
import os
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from sanna.cloud import load_constitution_from_cloud
from sanna.cloud.constitution import (
    ConstitutionFetchError,
    _MEMORY_CACHE,
    _write_disk_cache,
    _read_disk_cache_by_id,
)
from sanna.cloud._http import CloudHTTPError, CloudUnreachableError
from sanna.constitution import (
    AgentIdentity,
    Boundary,
    Constitution,
    Invariant,
    Provenance,
    SannaConstitutionError,
    save_constitution,
    sign_constitution,
)
from sanna.crypto import generate_keypair


BASE_URL = "https://api.sanna.test"
CONSTITUTION_ID = "const-abc123"
API_KEY = "sk_test_key"


# =============================================================================
# Fixtures
# =============================================================================

@pytest.fixture(autouse=True)
def _clear_memory_cache():
    _MEMORY_CACHE.clear()
    yield
    _MEMORY_CACHE.clear()


@pytest.fixture()
def keypair(tmp_path):
    """Generate an Ed25519 keypair and return (priv_path, pub_path)."""
    keys_dir = tmp_path / "keys"
    keys_dir.mkdir(parents=True, exist_ok=True)
    priv_path, pub_path = generate_keypair(keys_dir)
    return str(priv_path), str(pub_path)


@pytest.fixture()
def signed_constitution_yaml(tmp_path, keypair):
    """Return signed constitution YAML bytes and the public key path."""
    priv_path, pub_path = keypair
    const = Constitution(
        schema_version="1.0.0",
        identity=AgentIdentity(agent_name="cloud-test-agent", domain="testing"),
        provenance=Provenance(
            authored_by="author@test.com",
            approved_by=["approver@test.com"],
            approval_date="2026-01-01",
            approval_method="test",
        ),
        boundaries=[
            Boundary(id="B001", description="Test boundary", category="scope", severity="medium"),
        ],
        invariants=[
            Invariant(id="INV001", rule="Do not fabricate.", enforcement="halt"),
        ],
    )
    signed = sign_constitution(const, private_key_path=priv_path, signed_by="test")
    path = tmp_path / "constitution.yaml"
    save_constitution(signed, path)
    return path.read_bytes(), pub_path


def _make_mock_response(status: int, body: bytes, headers: dict | None = None) -> MagicMock:
    """Build a mock urllib response context manager."""
    resp = MagicMock()
    resp.status = status
    resp.read.return_value = body
    resp.headers = MagicMock()
    resp.headers.items.return_value = list((headers or {}).items())
    resp.headers.get = lambda k, d=None: (headers or {}).get(k, d)
    cm = MagicMock()
    cm.__enter__ = MagicMock(return_value=resp)
    cm.__exit__ = MagicMock(return_value=False)
    return cm


# =============================================================================
# AC #1: fetch + parse + verify + return Constitution
# =============================================================================

def test_fetch_success_end_to_end(signed_constitution_yaml, monkeypatch):
    """Successful fetch, parse, and Ed25519 signature verification."""
    yaml_bytes, pub_path = signed_constitution_yaml

    monkeypatch.delenv("SANNA_CONSTITUTION_PUBLIC_KEY", raising=False)

    with patch("urllib.request.urlopen", return_value=_make_mock_response(200, yaml_bytes)):
        result = load_constitution_from_cloud(
            CONSTITUTION_ID,
            BASE_URL,
            API_KEY,
            constitution_public_key_path=pub_path,
            cache_ttl_seconds=0,
        )

    assert isinstance(result, Constitution)
    assert result.identity.agent_name == "cloud-test-agent"


# =============================================================================
# AC #3: Cloud unreachable + no allow_cached_startup → ConstitutionFetchError
# =============================================================================

def test_cloud_unreachable_no_override_raises(monkeypatch):
    """Cloud unreachable with default settings → ConstitutionFetchError (fail-closed)."""
    import urllib.error

    monkeypatch.delenv("SANNA_CONSTITUTION_PUBLIC_KEY", raising=False)

    with patch("urllib.request.urlopen", side_effect=urllib.error.URLError("connection refused")):
        with pytest.raises(ConstitutionFetchError, match="Refusing to start"):
            load_constitution_from_cloud(
                CONSTITUTION_ID,
                BASE_URL,
                API_KEY,
                cache_ttl_seconds=0,
            )


# =============================================================================
# AC #4: Cloud unreachable + allow_cached_startup + disk cache hit → stale cached + warning
# =============================================================================

def test_cloud_unreachable_with_override_uses_disk_cache(tmp_path, signed_constitution_yaml, monkeypatch, caplog):
    """Cloud unreachable + allow_cached_startup=True + disk cache hit → returns cached + logs warning."""
    import logging
    import urllib.error

    yaml_bytes, pub_path = signed_constitution_yaml

    monkeypatch.delenv("SANNA_CONSTITUTION_PUBLIC_KEY", raising=False)

    # Pre-populate disk cache
    _write_disk_cache(CONSTITUTION_ID, None, yaml_bytes, tmp_path)

    with patch("urllib.request.urlopen", side_effect=urllib.error.URLError("network down")):
        with caplog.at_level(logging.WARNING, logger="sanna.cloud.constitution"):
            result = load_constitution_from_cloud(
                CONSTITUTION_ID,
                BASE_URL,
                API_KEY,
                constitution_public_key_path=pub_path,
                cache_ttl_seconds=0,
                disk_cache_enabled=True,
                disk_cache_dir=tmp_path,
                allow_cached_startup=True,
            )

    assert isinstance(result, Constitution)
    assert "disk cache" in caplog.text.lower()


# =============================================================================
# AC #5: In-memory cache hit within TTL does not make another HTTP call
# =============================================================================

def test_cache_hit_within_ttl_does_not_refetch(signed_constitution_yaml, monkeypatch):
    """Second call within TTL returns cached without hitting urlopen."""
    yaml_bytes, pub_path = signed_constitution_yaml

    monkeypatch.delenv("SANNA_CONSTITUTION_PUBLIC_KEY", raising=False)

    call_count = 0

    def counting_urlopen(req, timeout=None):
        nonlocal call_count
        call_count += 1
        return _make_mock_response(200, yaml_bytes)

    with patch("urllib.request.urlopen", side_effect=counting_urlopen):
        r1 = load_constitution_from_cloud(
            CONSTITUTION_ID,
            BASE_URL,
            API_KEY,
            constitution_public_key_path=pub_path,
            cache_ttl_seconds=60.0,
        )
        r2 = load_constitution_from_cloud(
            CONSTITUTION_ID,
            BASE_URL,
            API_KEY,
            constitution_public_key_path=pub_path,
            cache_ttl_seconds=60.0,
        )

    assert call_count == 1
    assert r1 is r2


# =============================================================================
# AC #6 (partial): SDK handles 304 from a mocked endpoint that emits ETag
# =============================================================================

def test_etag_protocol_ready_handles_304(signed_constitution_yaml, monkeypatch):
    """SDK sends If-None-Match and handles 304 Not Modified by returning cached.

    Strategy: use a real TTL so the first response is cached with its ETag.
    Expire the cache entry manually (backdate fetched_at), so the second call
    re-fetches rather than returning from in-memory cache. The server returns 304;
    the SDK must return the cached constitution.
    """
    import urllib.error

    yaml_bytes, pub_path = signed_constitution_yaml

    monkeypatch.delenv("SANNA_CONSTITUTION_PUBLIC_KEY", raising=False)

    sent_headers: list[dict] = []
    call_count = 0

    def capturing_urlopen(req, timeout=None):
        nonlocal call_count
        sent_headers.append(dict(req.headers))
        call_count += 1
        if call_count == 1:
            return _make_mock_response(200, yaml_bytes, {"etag": '"abc123"'})
        # Second call: return 304
        err = urllib.error.HTTPError(
            req.full_url, 304, "Not Modified",
            MagicMock(**{"items.return_value": [], "get": lambda k, d=None: None}),
            None,
        )
        raise err

    cache_key = (BASE_URL.rstrip("/"), CONSTITUTION_ID, None)

    with patch("urllib.request.urlopen", side_effect=capturing_urlopen):
        # First fetch: populates cache with ETag
        r1 = load_constitution_from_cloud(
            CONSTITUTION_ID,
            BASE_URL,
            API_KEY,
            constitution_public_key_path=pub_path,
            cache_ttl_seconds=60.0,
        )
        # Expire the cache entry so TTL check fails on next call
        from sanna.cloud.constitution import _MEMORY_CACHE, _MEMORY_CACHE_LOCK
        with _MEMORY_CACHE_LOCK:
            if cache_key in _MEMORY_CACHE:
                const, _, etag = _MEMORY_CACHE[cache_key]
                _MEMORY_CACHE[cache_key] = (const, 0.0, etag)  # fetched_at=epoch → expired

        r2 = load_constitution_from_cloud(
            CONSTITUTION_ID,
            BASE_URL,
            API_KEY,
            constitution_public_key_path=pub_path,
            cache_ttl_seconds=60.0,
        )

    assert r1.identity.agent_name == r2.identity.agent_name
    assert call_count == 2
    # Second request must have included If-None-Match
    second_req_headers = sent_headers[1]
    header_keys_lower = {k.lower() for k in second_req_headers}
    assert "if-none-match" in header_keys_lower


# =============================================================================
# AC #7: Signature verification failure fails closed
# =============================================================================

def test_signature_verification_failure_fails_closed(tmp_path, signed_constitution_yaml, monkeypatch):
    """Constitution with wrong public key raises SannaConstitutionError."""
    yaml_bytes, _ = signed_constitution_yaml

    monkeypatch.delenv("SANNA_CONSTITUTION_PUBLIC_KEY", raising=False)

    # Generate a different keypair — wrong key for this constitution
    wrong_keys = tmp_path / "wrong_keys"
    wrong_keys.mkdir(parents=True, exist_ok=True)
    _, wrong_pub = generate_keypair(wrong_keys)

    with patch("urllib.request.urlopen", return_value=_make_mock_response(200, yaml_bytes)):
        with pytest.raises(SannaConstitutionError, match="signature verification failed"):
            load_constitution_from_cloud(
                CONSTITUTION_ID,
                BASE_URL,
                API_KEY,
                constitution_public_key_path=str(wrong_pub),
                cache_ttl_seconds=0,
            )


# =============================================================================
# Unsigned constitution fails closed
# =============================================================================

def test_unsigned_constitution_fails_closed(tmp_path, monkeypatch):
    """A constitution with no signature raises SannaConstitutionError."""
    from sanna.constitution import compute_constitution_hash

    monkeypatch.delenv("SANNA_CONSTITUTION_PUBLIC_KEY", raising=False)

    const = Constitution(
        schema_version="1.0.0",
        identity=AgentIdentity(agent_name="unsigned-agent", domain="testing"),
        provenance=Provenance(
            authored_by="author@test.com",
            approved_by=["approver@test.com"],
            approval_date="2026-01-01",
            approval_method="test",
        ),
        boundaries=[Boundary(id="B001", description="Test", category="scope", severity="medium")],
        invariants=[],
    )
    path = tmp_path / "unsigned.yaml"
    save_constitution(const, path)
    yaml_bytes = path.read_bytes()

    with patch("urllib.request.urlopen", return_value=_make_mock_response(200, yaml_bytes)):
        with pytest.raises(SannaConstitutionError, match="unsigned"):
            load_constitution_from_cloud(
                CONSTITUTION_ID,
                BASE_URL,
                API_KEY,
                cache_ttl_seconds=0,
            )


# =============================================================================
# Signed constitution + no public key in kwarg/env → SannaConstitutionError
# =============================================================================

def test_no_public_key_with_signed_constitution_fails(signed_constitution_yaml, monkeypatch):
    """Signed constitution + no public key configured → SannaConstitutionError."""
    yaml_bytes, _ = signed_constitution_yaml

    monkeypatch.delenv("SANNA_CONSTITUTION_PUBLIC_KEY", raising=False)

    with patch("urllib.request.urlopen", return_value=_make_mock_response(200, yaml_bytes)):
        with pytest.raises(SannaConstitutionError, match="no public key configured"):
            load_constitution_from_cloud(
                CONSTITUTION_ID,
                BASE_URL,
                API_KEY,
                cache_ttl_seconds=0,
            )


# =============================================================================
# cache_ttl_seconds=0 disables cache — every call fetches
# =============================================================================

def test_cache_disabled_always_fetches(signed_constitution_yaml, monkeypatch):
    """cache_ttl_seconds=0 means every call hits Cloud."""
    yaml_bytes, pub_path = signed_constitution_yaml

    monkeypatch.delenv("SANNA_CONSTITUTION_PUBLIC_KEY", raising=False)

    call_count = 0

    def counting_urlopen(req, timeout=None):
        nonlocal call_count
        call_count += 1
        return _make_mock_response(200, yaml_bytes)

    with patch("urllib.request.urlopen", side_effect=counting_urlopen):
        load_constitution_from_cloud(
            CONSTITUTION_ID, BASE_URL, API_KEY,
            constitution_public_key_path=pub_path,
            cache_ttl_seconds=0,
        )
        load_constitution_from_cloud(
            CONSTITUTION_ID, BASE_URL, API_KEY,
            constitution_public_key_path=pub_path,
            cache_ttl_seconds=0,
        )

    assert call_count == 2


# =============================================================================
# version=N appends ?version=N to URL
# =============================================================================

def test_explicit_version_param(signed_constitution_yaml, monkeypatch):
    """version=N appends ?version=N to the request URL."""
    yaml_bytes, pub_path = signed_constitution_yaml

    monkeypatch.delenv("SANNA_CONSTITUTION_PUBLIC_KEY", raising=False)

    captured_urls: list[str] = []

    def capturing_urlopen(req, timeout=None):
        captured_urls.append(req.full_url)
        return _make_mock_response(200, yaml_bytes)

    with patch("urllib.request.urlopen", side_effect=capturing_urlopen):
        load_constitution_from_cloud(
            CONSTITUTION_ID, BASE_URL, API_KEY,
            version=42,
            constitution_public_key_path=pub_path,
            cache_ttl_seconds=0,
        )

    assert captured_urls
    assert "?version=42" in captured_urls[0]


# =============================================================================
# 404 surfaces as CloudHTTPError with status=404
# =============================================================================

def test_404_surfaces_cleanly(monkeypatch):
    """Non-existent constitution_id → CloudHTTPError with status=404."""
    import urllib.error

    monkeypatch.delenv("SANNA_CONSTITUTION_PUBLIC_KEY", raising=False)

    def raise_404(req, timeout=None):
        raise urllib.error.HTTPError(
            req.full_url, 404, "Not Found",
            MagicMock(**{"items.return_value": [], "get": lambda k, d=None: None}),
            None,
        )

    with patch("urllib.request.urlopen", side_effect=raise_404):
        with pytest.raises(CloudHTTPError) as exc_info:
            load_constitution_from_cloud(
                "nonexistent-id",
                BASE_URL,
                API_KEY,
                cache_ttl_seconds=0,
            )

    assert exc_info.value.status == 404


# =============================================================================
# Disk cache round-trip: write then read with no Cloud call
# =============================================================================

def test_disk_cache_round_trip(tmp_path, signed_constitution_yaml, monkeypatch):
    """_write_disk_cache then _read_disk_cache_by_id returns matching bytes."""
    yaml_bytes, _ = signed_constitution_yaml

    monkeypatch.delenv("SANNA_CONSTITUTION_PUBLIC_KEY", raising=False)

    _write_disk_cache(CONSTITUTION_ID, None, yaml_bytes, tmp_path)
    result = _read_disk_cache_by_id(CONSTITUTION_ID, None, tmp_path)

    assert result is not None
    stored_bytes, content_hash = result
    assert stored_bytes == yaml_bytes

    # Versioned key is separate from 'latest'
    result_versioned = _read_disk_cache_by_id(CONSTITUTION_ID, 1, tmp_path)
    assert result_versioned is None

    _write_disk_cache(CONSTITUTION_ID, 1, yaml_bytes, tmp_path)
    result_versioned = _read_disk_cache_by_id(CONSTITUTION_ID, 1, tmp_path)
    assert result_versioned is not None
    assert result_versioned[0] == yaml_bytes
