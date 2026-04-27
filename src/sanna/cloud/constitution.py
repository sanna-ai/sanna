"""Cloud constitution fetch client.

Loads constitutions from sanna-cloud's GET /v1/constitutions/{id}/export
endpoint, with caching, signature verification, and fail-closed-on-unreachable
semantics.

Per ADR / SAN-215: the disk cache is keyed on content hash. Documented caveat:
hash-keyed caching cannot propagate revocation without a Cloud round-trip that
defeats the cache. Use cache_ttl_seconds=0 + disk_cache_enabled=False for
high-assurance deployments where every fetch must hit Cloud.

Disk cache index key encoding: f"{constitution_id}::{version if version is not None else 'latest'}"
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import threading
import time
from pathlib import Path
from typing import Optional

from sanna.constitution import (
    Constitution,
    SannaConstitutionError,
    parse_constitution_from_yaml_bytes,
)
from sanna.cloud._http import CloudHTTPError, CloudUnreachableError, http_get

logger = logging.getLogger(__name__)


# In-memory cache: {(base_url, constitution_id, version): (Constitution, fetched_at, etag)}
_MEMORY_CACHE: dict[tuple[str, str, Optional[int]], tuple[Constitution, float, Optional[str]]] = {}
_MEMORY_CACHE_LOCK = threading.Lock()


class ConstitutionFetchError(Exception):
    """Top-level error for Cloud constitution fetches."""
    pass


def load_constitution_from_cloud(
    constitution_id: str,
    base_url: str,
    api_key: str,
    *,
    version: Optional[int] = None,
    constitution_public_key_path: Optional[str | Path] = None,
    cache_ttl_seconds: float = 60.0,
    disk_cache_enabled: bool = False,
    disk_cache_dir: Optional[str | Path] = None,
    allow_cached_startup: bool = False,
    timeout_seconds: float = 10.0,
    max_retries: int = 3,
    validate: bool = False,
) -> Constitution:
    """Fetch a constitution from sanna-cloud and return a verified Constitution.

    Calls GET /v1/constitutions/{constitution_id}/export, parses YAML, verifies
    Ed25519 signature (full-document scheme), and returns a Constitution dataclass.

    Args:
        constitution_id: Cloud constitution ID.
        base_url: Cloud API base URL (e.g., "https://api.sanna.cloud"). The /v1
            prefix is appended automatically.
        api_key: API key for Authorization: Bearer <key>.
        version: Optional specific version number. Default: current active version.
        constitution_public_key_path: Path to Ed25519 public key (PEM) for
            signature verification. If None, falls back to SANNA_CONSTITUTION_PUBLIC_KEY
            env var (with key_id match check). If neither resolves to a valid key
            and the constitution has a signature, the call fails closed.
        cache_ttl_seconds: In-memory cache TTL. Default 60s. Set 0 to disable.
        disk_cache_enabled: Opt-in disk cache at disk_cache_dir, keyed on content hash.
        disk_cache_dir: Disk cache directory. Default: ~/.sanna/constitutions.
        allow_cached_startup: If True, allow startup with cached constitution when
            Cloud is unreachable (logs a staleness warning). Default False (fail closed).
        timeout_seconds: Per-request HTTP timeout. Default 10s.
        max_retries: HTTP retry count. Default 3.
        validate: If True, validate parsed constitution against the JSON schema.

    Returns:
        Constitution dataclass.

    Raises:
        ConstitutionFetchError: Cloud unreachable + no override / cache, or
            unexpected fetch failure.
        SannaConstitutionError: Signature verification failure or parse error.
        CloudHTTPError: Non-retryable HTTP error (404, 403, etc.).

    Behavior:
        - In-memory cache hit within TTL: returns cached, no Cloud call.
        - Cache miss + Cloud reachable: fetches, parses, verifies, caches.
        - Cache miss + Cloud unreachable + allow_cached_startup=False: raises
          ConstitutionFetchError.
        - Cache miss + Cloud unreachable + allow_cached_startup=True + disk
          cache hit: returns cached + logs a staleness warning.
        - Cache miss + Cloud unreachable + allow_cached_startup=True + no disk
          cache: raises ConstitutionFetchError (override has nothing to fall
          back to).
        - Conditional request: if a cached entry has an ETag, sends
          If-None-Match. On 304, returns cached unchanged. (Cloud does not
          currently emit ETag — the SDK is protocol-ready for when it does.)
    """
    cache_key = (base_url.rstrip("/"), constitution_id, version)

    # 1. In-memory cache hit?
    if cache_ttl_seconds > 0:
        with _MEMORY_CACHE_LOCK:
            cached = _MEMORY_CACHE.get(cache_key)
        if cached is not None:
            cached_constitution, fetched_at, _ = cached
            age = time.time() - fetched_at
            if age <= cache_ttl_seconds:
                return cached_constitution

    # 2. Build request URL + conditional headers
    url = _build_export_url(base_url, constitution_id, version)
    request_headers: dict[str, str] = {}
    if cache_ttl_seconds > 0:
        with _MEMORY_CACHE_LOCK:
            stale = _MEMORY_CACHE.get(cache_key)
        if stale is not None and stale[2] is not None:
            request_headers["If-None-Match"] = stale[2]

    # 3. Fetch
    try:
        status, body, headers = http_get(
            url,
            api_key,
            headers=request_headers,
            timeout_seconds=timeout_seconds,
            max_retries=max_retries,
        )
    except CloudUnreachableError as e:
        return _handle_unreachable(
            cache_key, constitution_id, version,
            disk_cache_enabled, disk_cache_dir, allow_cached_startup,
            constitution_public_key_path, validate, e,
        )

    # 4. 304 Not Modified — return cached with refreshed TTL
    if status == 304:
        with _MEMORY_CACHE_LOCK:
            cached = _MEMORY_CACHE.get(cache_key)
        if cached is None:
            raise ConstitutionFetchError(
                "Cloud returned 304 Not Modified but no cached constitution exists."
            )
        cached_constitution, _, etag = cached
        with _MEMORY_CACHE_LOCK:
            _MEMORY_CACHE[cache_key] = (cached_constitution, time.time(), etag)
        return cached_constitution

    # 5. 200 OK: parse, verify, cache
    constitution = parse_constitution_from_yaml_bytes(body, validate=validate)
    _verify_signature(constitution, constitution_public_key_path)

    etag = headers.get("etag")  # case-folded by http_get

    if cache_ttl_seconds > 0:
        with _MEMORY_CACHE_LOCK:
            _MEMORY_CACHE[cache_key] = (constitution, time.time(), etag)

    if disk_cache_enabled:
        _write_disk_cache(constitution_id, version, body, disk_cache_dir)

    return constitution


def _build_export_url(base_url: str, constitution_id: str, version: Optional[int]) -> str:
    base = base_url.rstrip("/")
    url = f"{base}/v1/constitutions/{constitution_id}/export"
    if version is not None:
        url = f"{url}?version={version}"
    return url


def _cache_index_key(constitution_id: str, version: Optional[int]) -> str:
    """Flat key encoding for the disk cache index."""
    return f"{constitution_id}::{version if version is not None else 'latest'}"


def _resolve_public_key_path(
    constitution: Constitution,
    explicit_path: Optional[str | Path],
) -> Optional[str]:
    """Resolve public key per the middleware.py pattern: explicit > env var (with key_id match)."""
    if explicit_path:
        return str(explicit_path)
    env_key = os.environ.get("SANNA_CONSTITUTION_PUBLIC_KEY")
    if env_key and os.path.isfile(env_key):
        try:
            from sanna.crypto import load_public_key, compute_key_id
            env_pub = load_public_key(env_key)
            env_key_id = compute_key_id(env_pub)
            const_sig = constitution.provenance.signature if constitution.provenance else None
            if const_sig and getattr(const_sig, "key_id", None) == env_key_id:
                return env_key
        except Exception:
            pass
    return None


def _verify_signature(
    constitution: Constitution,
    explicit_public_key_path: Optional[str | Path],
) -> None:
    """Verify the constitution's signature. Fails closed on missing or invalid signature."""
    sig = constitution.provenance.signature if constitution.provenance else None
    if sig is None or not sig.value:
        raise SannaConstitutionError(
            "Cloud-fetched constitution is unsigned. Refusing to load. "
            "Ensure the constitution was signed before upload to Cloud."
        )

    public_key_path = _resolve_public_key_path(constitution, explicit_public_key_path)
    if not public_key_path:
        raise SannaConstitutionError(
            "Constitution has signature but no public key configured to verify it. "
            "Provide constitution_public_key_path kwarg or set SANNA_CONSTITUTION_PUBLIC_KEY env var."
        )

    from sanna.crypto import verify_constitution_full
    if not verify_constitution_full(constitution, public_key_path):
        raise SannaConstitutionError(
            "Cloud-fetched constitution signature verification failed. "
            "The constitution may have been tampered with or the wrong public key was provided."
        )


def _handle_unreachable(
    cache_key: tuple[str, str, Optional[int]],
    constitution_id: str,
    version: Optional[int],
    disk_cache_enabled: bool,
    disk_cache_dir: Optional[str | Path],
    allow_cached_startup: bool,
    explicit_public_key_path: Optional[str | Path],
    validate: bool,
    original_error: Exception,
) -> Constitution:
    """Fail-closed-on-unreachable handler."""
    if not allow_cached_startup:
        raise ConstitutionFetchError(
            f"Cloud unreachable while fetching constitution {constitution_id} "
            f"(version={version}). Refusing to start without cache override. "
            f"Pass allow_cached_startup=True to fall back to disk cache in dev/CI. "
            f"Underlying error: {original_error}"
        )

    if not disk_cache_enabled:
        raise ConstitutionFetchError(
            f"Cloud unreachable + allow_cached_startup=True but disk cache is disabled. "
            f"Enable disk_cache_enabled=True for the override to have a fallback. "
            f"Underlying error: {original_error}"
        )

    cached = _read_disk_cache_by_id(constitution_id, version, disk_cache_dir)
    if cached is None:
        raise ConstitutionFetchError(
            f"Cloud unreachable + override on, but no disk cache hit for "
            f"constitution {constitution_id} (version={version}). "
            f"Underlying error: {original_error}"
        )

    constitution_yaml_bytes, content_hash = cached
    constitution = parse_constitution_from_yaml_bytes(constitution_yaml_bytes, validate=validate)
    _verify_signature(constitution, explicit_public_key_path)

    logger.warning(
        "Cloud unreachable; loaded constitution %s (version=%s) from disk cache (content_hash=%s). "
        "Stale data possible. Underlying error: %s",
        constitution_id, version, content_hash, original_error,
    )

    return constitution


def _disk_cache_path(disk_cache_dir: Optional[str | Path]) -> Path:
    if disk_cache_dir:
        return Path(disk_cache_dir)
    return Path.home() / ".sanna" / "constitutions"


def _write_disk_cache(
    constitution_id: str,
    version: Optional[int],
    body: bytes,
    disk_cache_dir: Optional[str | Path],
) -> None:
    """Write constitution bytes to disk, keyed on content hash. Best-effort."""
    try:
        cache_dir = _disk_cache_path(disk_cache_dir)
        cache_dir.mkdir(parents=True, exist_ok=True)

        content_hash = hashlib.sha256(body).hexdigest()
        content_path = cache_dir / f"{content_hash}.yaml"
        if not content_path.exists():
            content_path.write_bytes(body)

        index_path = cache_dir / "index.json"
        index: dict[str, str] = {}
        if index_path.exists():
            try:
                index = json.loads(index_path.read_text())
            except Exception:
                index = {}

        index[_cache_index_key(constitution_id, version)] = content_hash
        index_path.write_text(json.dumps(index))
    except Exception as e:
        logger.warning("Failed to write disk cache: %s", e)


def _read_disk_cache_by_id(
    constitution_id: str,
    version: Optional[int],
    disk_cache_dir: Optional[str | Path],
) -> Optional[tuple[bytes, str]]:
    """Read the cached YAML bytes for a (constitution_id, version). Returns (bytes, content_hash) or None."""
    try:
        cache_dir = _disk_cache_path(disk_cache_dir)
        index_path = cache_dir / "index.json"
        if not index_path.exists():
            return None

        index = json.loads(index_path.read_text())
        content_hash = index.get(_cache_index_key(constitution_id, version))
        if content_hash is None:
            return None

        content_path = cache_dir / f"{content_hash}.yaml"
        if not content_path.exists():
            return None

        body = content_path.read_bytes()
        return body, content_hash
    except Exception as e:
        logger.warning("Failed to read disk cache: %s", e)
        return None
