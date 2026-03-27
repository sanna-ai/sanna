"""CloudHTTPSink — sends receipts to Sanna Cloud via HTTPS POST.

Uses ``urllib.request`` (stdlib only) consistent with the existing
``sanna.evaluators.llm`` LLMJudge pattern. No requests/httpx dependency.
"""

from __future__ import annotations

import json
import logging
from sanna.utils.safe_json import safe_json_loads
import os
import random
import threading
import time
import urllib.error
import urllib.request
from typing import Any

from .sink import ReceiptSink, SinkResult, FailurePolicy

logger = logging.getLogger("sanna.sinks.cloud")

# HTTP status codes with specific handling
_NO_RETRY_STATUSES = frozenset({400, 401, 403})
_SUCCESS_STATUSES = frozenset({200, 201})
_DUPLICATE_STATUS = 409


class CloudHTTPSink(ReceiptSink):
    """Send receipts to Sanna Cloud ingestion API via HTTPS POST.

    Args:
        api_url: Cloud ingestion endpoint (e.g. ``https://api.sanna.dev/v1/receipts``).
        api_key: Scoped API key with ``receipts:write`` scope.
        failure_policy: Default ``LOG_AND_CONTINUE``.
        timeout_seconds: HTTP request timeout. Default ``10.0``.
        max_retries: Max retry attempts for retryable errors. Default ``3``.
        retry_backoff_base: Exponential backoff base in seconds. Default ``1.0``.
        batch_size: Max receipts per batch POST. Default ``50``.
        buffer_path: File path for BUFFER_AND_RETRY persistence. Required if
            policy is BUFFER_AND_RETRY.
    """

    def __init__(
        self,
        api_url: str,
        api_key: str,
        failure_policy: FailurePolicy = FailurePolicy.LOG_AND_CONTINUE,
        timeout_seconds: float = 10.0,
        max_retries: int = 3,
        retry_backoff_base: float = 1.0,
        batch_size: int = 50,
        buffer_path: str | None = None,
    ) -> None:
        if not api_url:
            raise ValueError("api_url is required")
        if not api_key:
            raise ValueError("api_key is required")
        if failure_policy == FailurePolicy.BUFFER_AND_RETRY and not buffer_path:
            raise ValueError(
                "buffer_path is required when failure_policy is BUFFER_AND_RETRY"
            )

        self._api_url = api_url.rstrip("/")
        self._api_key = api_key
        self._failure_policy = failure_policy
        self._timeout = timeout_seconds
        self._max_retries = max_retries
        self._retry_backoff_base = retry_backoff_base
        self._batch_size = batch_size
        self._buffer_path = buffer_path

        from sanna.version import __version__
        self._user_agent = f"sanna-python/{__version__}"

        # Buffer-and-retry background thread
        self._buffer_lock = threading.Lock()
        self._retry_thread: threading.Thread | None = None
        self._stop_event = threading.Event()

        if failure_policy == FailurePolicy.BUFFER_AND_RETRY:
            self._start_retry_thread()

    def _start_retry_thread(self) -> None:
        """Start background thread for retrying buffered receipts."""
        def _retry_loop() -> None:
            while not self._stop_event.wait(timeout=60):
                self._drain_buffer()

        self._retry_thread = threading.Thread(
            target=_retry_loop, daemon=True, name="sanna-cloud-retry",
        )
        self._retry_thread.start()

    def _build_headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self._api_key}",
            "Content-Type": "application/json",
            "User-Agent": self._user_agent,
        }

    def _post_with_retry(
        self, url: str, body: bytes,
    ) -> tuple[int, str]:
        """POST with exponential backoff retry. Returns (status_code, response_body)."""
        headers = self._build_headers()
        last_error = ""

        for attempt in range(self._max_retries + 1):
            try:
                req = urllib.request.Request(
                    url, data=body, headers=headers, method="POST",
                )
                with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                    return resp.status, resp.read().decode("utf-8", errors="replace")
            except urllib.error.HTTPError as e:
                status = e.code
                resp_body = ""
                try:
                    resp_body = e.read().decode("utf-8", errors="replace")
                except OSError:
                    pass

                # Duplicate — treat as success
                if status == _DUPLICATE_STATUS:
                    return status, resp_body

                # Non-retryable
                if status in _NO_RETRY_STATUSES:
                    return status, resp_body

                # Retryable (429, 503, 5xx)
                last_error = f"HTTP {status}: {resp_body[:200]}"
                retry_after = e.headers.get("Retry-After") if e.headers else None
                if retry_after:
                    try:
                        delay = float(retry_after)
                    except ValueError:
                        delay = self._backoff_delay(attempt)
                else:
                    delay = self._backoff_delay(attempt)

                if attempt < self._max_retries:
                    logger.debug(
                        "CloudHTTPSink: retrying in %.1fs (attempt %d/%d): %s",
                        delay, attempt + 1, self._max_retries, last_error,
                    )
                    time.sleep(delay)
                    continue
                return status, resp_body

            except (urllib.error.URLError, TimeoutError, OSError) as e:
                last_error = str(e)
                if attempt < self._max_retries:
                    delay = self._backoff_delay(attempt)
                    logger.debug(
                        "CloudHTTPSink: retrying in %.1fs (attempt %d/%d): %s",
                        delay, attempt + 1, self._max_retries, last_error,
                    )
                    time.sleep(delay)
                    continue
                return 0, last_error

        return 0, last_error

    def _backoff_delay(self, attempt: int) -> float:
        return self._retry_backoff_base * (2 ** attempt) + random.uniform(0, 0.5)

    def store(self, receipt: dict) -> SinkResult:
        url = f"{self._api_url}/v1/receipts"
        body = json.dumps(receipt).encode("utf-8")

        status, resp_body = self._post_with_retry(url, body)

        if status in _SUCCESS_STATUSES or status == _DUPLICATE_STATUS:
            return SinkResult(stored=1)

        error_msg = f"CloudHTTPSink: POST failed (status={status}): {resp_body[:200]}"
        logger.warning(error_msg)

        if self._failure_policy == FailurePolicy.BUFFER_AND_RETRY:
            self._buffer_receipt(receipt)
            return SinkResult(stored=0, failed=1, errors=(error_msg,))
        elif self._failure_policy == FailurePolicy.RAISE:
            raise RuntimeError(error_msg)

        return SinkResult(failed=1, errors=(error_msg,))

    def batch_store(self, receipts: list[dict]) -> SinkResult:
        stored, failed, errors = 0, 0, []

        for i in range(0, len(receipts), self._batch_size):
            chunk = receipts[i : i + self._batch_size]
            url = f"{self._api_url}/v1/receipts/batch"
            body = json.dumps({"receipts": chunk}).encode("utf-8")

            status, resp_body = self._post_with_retry(url, body)

            if status in _SUCCESS_STATUSES or status == _DUPLICATE_STATUS:
                stored += len(chunk)
            else:
                error_msg = (
                    f"CloudHTTPSink: batch POST failed "
                    f"(status={status}): {resp_body[:200]}"
                )
                logger.warning(error_msg)
                failed += len(chunk)
                errors.append(error_msg)

                if self._failure_policy == FailurePolicy.BUFFER_AND_RETRY:
                    for r in chunk:
                        self._buffer_receipt(r)
                elif self._failure_policy == FailurePolicy.RAISE:
                    raise RuntimeError(error_msg)

        return SinkResult(stored=stored, failed=failed, errors=tuple(errors))

    # -- Buffer-and-retry persistence ------------------------------------------

    def _buffer_receipt(self, receipt: dict) -> None:
        """Append receipt to JSONL buffer file."""
        if not self._buffer_path:
            return
        with self._buffer_lock:
            try:
                from pathlib import Path
                parent = Path(self._buffer_path).parent
                parent.mkdir(parents=True, exist_ok=True)
                with open(self._buffer_path, "a") as f:
                    f.write(json.dumps(receipt) + "\n")
            except OSError as e:
                logger.error("CloudHTTPSink: failed to buffer receipt: %s", e)

    def _drain_buffer(self) -> None:
        """Read buffered receipts and retry sending."""
        if not self._buffer_path or not os.path.exists(self._buffer_path):
            return

        with self._buffer_lock:
            try:
                with open(self._buffer_path, "r") as f:
                    lines = f.readlines()
            except OSError:
                return

            if not lines:
                return

            remaining: list[str] = []
            for line in lines:
                line = line.strip()
                if not line:
                    continue
                try:
                    receipt = safe_json_loads(line)
                except (json.JSONDecodeError, ValueError):
                    logger.warning("CloudHTTPSink: skipping malformed buffer line")
                    continue

                url = f"{self._api_url}/v1/receipts"
                body = json.dumps(receipt).encode("utf-8")
                status, _ = self._post_with_retry(url, body)

                if status not in _SUCCESS_STATUSES and status != _DUPLICATE_STATUS:
                    remaining.append(json.dumps(receipt) + "\n")

            try:
                with open(self._buffer_path, "w") as f:
                    f.writelines(remaining)
            except OSError as e:
                logger.error("CloudHTTPSink: failed to update buffer: %s", e)

    def flush(self) -> None:
        """Block until buffer is drained or timeout (30s)."""
        if not self._buffer_path:
            return
        deadline = time.monotonic() + 30.0
        while time.monotonic() < deadline:
            if not os.path.exists(self._buffer_path):
                return
            try:
                with open(self._buffer_path, "r") as f:
                    content = f.read().strip()
                if not content:
                    return
            except OSError:
                return
            self._drain_buffer()
            time.sleep(0.5)

    def close(self) -> None:
        self._stop_event.set()
        if self._retry_thread and self._retry_thread.is_alive():
            self._retry_thread.join(timeout=5.0)
