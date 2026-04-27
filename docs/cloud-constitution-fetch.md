# Cloud Constitution Fetch

The `sanna.cloud` subpackage provides a client for fetching constitutions managed in Sanna Cloud. `load_constitution_from_cloud` is the primary entry point.

## Quick start

```python
from sanna.cloud import load_constitution_from_cloud

constitution = load_constitution_from_cloud(
    constitution_id="const-abc123",
    base_url="https://api.sanna.cloud",
    api_key="sk_live_...",
    constitution_public_key_path="/etc/sanna/keys/my-org.pub",
)
```

## API reference

### `load_constitution_from_cloud(...) -> Constitution`

```python
def load_constitution_from_cloud(
    constitution_id: str,
    base_url: str,
    api_key: str,
    *,
    version: int | None = None,
    constitution_public_key_path: str | Path | None = None,
    cache_ttl_seconds: float = 60.0,
    disk_cache_enabled: bool = False,
    disk_cache_dir: str | Path | None = None,
    allow_cached_startup: bool = False,
    timeout_seconds: float = 10.0,
    max_retries: int = 3,
    validate: bool = False,
) -> Constitution
```

**Parameters**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `constitution_id` | `str` | required | Cloud constitution ID. |
| `base_url` | `str` | required | Cloud API base URL (e.g. `"https://api.sanna.cloud"`). The `/v1` prefix is appended automatically. |
| `api_key` | `str` | required | API key sent as `Authorization: Bearer <key>`. Must have at least `viewer` role. |
| `version` | `int \| None` | `None` | Specific version to fetch. Default: current active version. |
| `constitution_public_key_path` | `str \| Path \| None` | `None` | Path to the Ed25519 public key (PEM) used for signature verification. See [Public key resolution](#public-key-resolution). |
| `cache_ttl_seconds` | `float` | `60.0` | In-memory cache TTL in seconds. Set to `0` to disable caching entirely. |
| `disk_cache_enabled` | `bool` | `False` | Enable disk cache for the `allow_cached_startup` fallback path. |
| `disk_cache_dir` | `str \| Path \| None` | `None` | Directory for the disk cache. Default: `~/.sanna/constitutions/`. |
| `allow_cached_startup` | `bool` | `False` | If `True`, fall back to disk cache when Cloud is unreachable. See [Fail-closed behavior](#fail-closed-behavior). |
| `timeout_seconds` | `float` | `10.0` | Per-request HTTP timeout. |
| `max_retries` | `int` | `3` | Maximum retry attempts for retryable errors (429, 5xx). |
| `validate` | `bool` | `False` | Validate the parsed constitution against the JSON schema before returning. |

**Returns** `Constitution` dataclass.

**Raises**

- `ConstitutionFetchError` — Cloud unreachable + no usable cache, or other fetch failure.
- `SannaConstitutionError` — Signature verification failure, parse error, or hash integrity violation.
- `CloudHTTPError` — Non-retryable HTTP error from Cloud (e.g. 404, 403).

## Public key resolution

Signature verification is **always required** for Cloud-fetched constitutions. The public key is resolved in this order:

1. **Explicit kwarg** — `constitution_public_key_path=<path>` takes priority.
2. **Environment variable** — `SANNA_CONSTITUTION_PUBLIC_KEY=<path>` is used when the env key's `key_id` matches the constitution's signature `key_id`. This prevents accidentally using the wrong key.

If neither resolves to a usable key, the call fails with `SannaConstitutionError`. There is no permissive fallback — unsigned or unverifiable Cloud constitutions are always rejected.

This matches the resolution order in `sanna.middleware.sanna_observe` (see `src/sanna/middleware.py:1010-1023`).

## Fail-closed behavior

By default (`allow_cached_startup=False`), if Cloud is unreachable during a fetch, the function raises `ConstitutionFetchError` immediately. This ensures no process starts with an unverified or potentially stale constitution.

The `allow_cached_startup=True` override enables a fallback to disk cache. This is useful in dev/CI where Cloud availability isn't guaranteed at startup. The fallback chain:

```
Cloud unreachable
  → allow_cached_startup=False (default) → ConstitutionFetchError
  → allow_cached_startup=True + disk_cache_enabled=False → ConstitutionFetchError
  → allow_cached_startup=True + disk_cache_enabled=True + no cache entry → ConstitutionFetchError
  → allow_cached_startup=True + disk_cache_enabled=True + cache hit
      → parse + verify signature + log WARNING + return Constitution
```

Even when falling back to disk cache, signature verification is always applied.

## Caching

### In-memory cache

Constitutions are cached in memory, keyed on `(base_url, constitution_id, version)`. Default TTL is 60 seconds.

- Set `cache_ttl_seconds=0` to disable entirely. Recommended for high-assurance deployments where every evaluation must reflect the latest Cloud constitution.
- Set a longer TTL (e.g. `cache_ttl_seconds=300`) for latency-sensitive deployments where a stale window is acceptable.

### Disk cache

The disk cache is opt-in (`disk_cache_enabled=True`). It is **only** used as the `allow_cached_startup` fallback when Cloud is unreachable. Successful Cloud fetches write to the disk cache automatically when enabled.

**Revocation caveat**: The disk cache is keyed on content hash. This means a revoked constitution will continue to be served from disk cache until a successful Cloud round-trip replaces the cached entry. Do not rely on `allow_cached_startup=True` in environments where constitution revocation must propagate immediately. Use `cache_ttl_seconds=0` + `disk_cache_enabled=False` for high-assurance deployments.

## ETag protocol readiness

The SDK is protocol-ready for HTTP conditional requests. When a cached entry has an `ETag`, subsequent fetches include `If-None-Match: <etag>` and handle `304 Not Modified` by returning the cached constitution with a refreshed TTL.

Sanna Cloud does not currently emit `ETag` headers — server-side header emission is a follow-up ticket. Until that ships, every fetch returns `200` with the full YAML body.

## HTTP behavior

- **Auth**: `Authorization: Bearer <api_key>` on every request.
- **Transport**: stdlib `urllib` only. No `httpx`, `requests`, or `aiohttp` dependency.
- **Retries**: up to `max_retries` retries with exponential backoff and jitter. `Retry-After` header respected when present.
- **Non-retryable**: 400, 401, 403, 404, 422 — surfaced immediately as `CloudHTTPError`.
- **Retryable**: 429, 500, 502, 503, 504.

## Production configuration recommendations

| Scenario | Recommended settings |
|----------|----------------------|
| Standard production | `cache_ttl_seconds=60` (default), `disk_cache_enabled=False`, `allow_cached_startup=False` |
| High-assurance (no stale window) | `cache_ttl_seconds=0`, `disk_cache_enabled=False`, `allow_cached_startup=False` |
| Dev / CI with optional Cloud | `cache_ttl_seconds=60`, `disk_cache_enabled=True`, `allow_cached_startup=True` |
| Low-latency, revocation lag acceptable | `cache_ttl_seconds=300`, `disk_cache_enabled=True`, `allow_cached_startup=False` |
