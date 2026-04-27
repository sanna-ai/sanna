"""Internal HTTP helper for Cloud client modules.

Mirrors the retry / timeout / backoff pattern from src/sanna/sinks/cloud.py
(CloudHTTPSink). Stdlib urllib only — keeping the SDK free of external HTTP
dependencies.

Per ticket: separate from CloudHTTPSink because sinks (POST receipts) and
clients (GET resources) have diverging auth and error models. Refactoring
into a shared CloudClient is explicitly out of scope.
"""

from __future__ import annotations

import logging
import random
import time
import urllib.error
import urllib.request
from typing import Optional

logger = logging.getLogger(__name__)

# Status codes that should NOT be retried (client errors, auth errors).
_NON_RETRYABLE_STATUS = frozenset({400, 401, 403, 404, 422})

# Status codes that SHOULD be retried (server errors, rate limits).
_RETRYABLE_STATUS = frozenset({429, 500, 502, 503, 504})


class CloudHTTPError(Exception):
    """HTTP error from a Cloud endpoint. Carries status + message."""

    def __init__(self, status: int, message: str, body: bytes | None = None):
        super().__init__(f"HTTP {status}: {message}")
        self.status = status
        self.message = message
        self.body = body


class CloudUnreachableError(Exception):
    """Network error: Cloud endpoint cannot be reached after retries."""
    pass


def http_get(
    url: str,
    api_key: str,
    *,
    headers: Optional[dict[str, str]] = None,
    timeout_seconds: float = 10.0,
    max_retries: int = 3,
    retry_backoff_base: float = 1.0,
) -> tuple[int, bytes, dict[str, str]]:
    """GET with bearer auth + exponential-backoff retry. Returns (status, body, response_headers).

    Args:
        url: Full URL to request.
        api_key: API key for `Authorization: Bearer <key>` header.
        headers: Additional headers to include (e.g., If-None-Match).
        timeout_seconds: Per-request timeout.
        max_retries: Total attempts is max_retries + 1 (initial + retries).
        retry_backoff_base: Backoff base in seconds; delay = base * 2^attempt + jitter.

    Returns:
        (status_code, response_body_bytes, response_headers).

    Raises:
        CloudHTTPError: non-retryable HTTP error from the server.
        CloudUnreachableError: network unreachable / all retries exhausted.
    """
    request_headers = {
        "Authorization": f"Bearer {api_key}",
        **(headers or {}),
    }

    last_error: Exception | None = None

    for attempt in range(max_retries + 1):
        try:
            req = urllib.request.Request(url, headers=request_headers, method="GET")
            with urllib.request.urlopen(req, timeout=timeout_seconds) as resp:
                status = resp.status
                body = resp.read()
                resp_headers = {k.lower(): v for k, v in resp.headers.items()}
                return status, body, resp_headers

        except urllib.error.HTTPError as e:
            status = e.code
            try:
                body = e.read()
            except Exception:
                body = b""
            try:
                message = body.decode("utf-8", errors="replace")
            except Exception:
                message = str(e)

            if status in _NON_RETRYABLE_STATUS:
                raise CloudHTTPError(status, message, body) from e

            if status == 304:
                # Not Modified — caller-handleable; pass through with empty body.
                resp_headers = {k.lower(): v for k, v in (e.headers or {}).items()}
                return 304, b"", resp_headers

            if attempt >= max_retries:
                raise CloudHTTPError(status, message, body) from e

            # Retryable status: respect Retry-After if present, else backoff.
            retry_after = e.headers.get("Retry-After") if e.headers else None
            if retry_after:
                try:
                    delay = float(retry_after)
                except ValueError:
                    delay = _backoff_delay(attempt, retry_backoff_base)
            else:
                delay = _backoff_delay(attempt, retry_backoff_base)

            logger.warning(
                "Cloud GET %s returned %d; retrying in %.2fs (attempt %d/%d)",
                url, status, delay, attempt + 1, max_retries,
            )
            time.sleep(delay)
            last_error = e
            continue

        except (urllib.error.URLError, TimeoutError, OSError) as e:
            last_error = e
            if attempt >= max_retries:
                raise CloudUnreachableError(
                    f"Cloud unreachable after {max_retries + 1} attempts: {e}"
                ) from e
            delay = _backoff_delay(attempt, retry_backoff_base)
            logger.warning(
                "Cloud GET %s network error: %s; retrying in %.2fs (attempt %d/%d)",
                url, e, delay, attempt + 1, max_retries,
            )
            time.sleep(delay)
            continue

    # Defensive — loop should have returned or raised by now.
    raise CloudUnreachableError(f"Cloud unreachable: {last_error}")


def _backoff_delay(attempt: int, base: float) -> float:
    """Exponential backoff with jitter. Mirrors CloudHTTPSink._backoff_delay."""
    return base * (2 ** attempt) + random.uniform(0, 0.5)
