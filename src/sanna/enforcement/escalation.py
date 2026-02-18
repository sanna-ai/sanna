"""
Sanna escalation handling — log, webhook, and callback escalation targets.

Provides the runtime execution layer for escalation actions triggered by
authority boundary enforcement. Supports three target types:

- **log**: Write to Python logging + return structured log entry (default)
- **webhook**: POST JSON payload to configured URL via httpx
- **callback**: Call a registered Python function from a global registry
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Optional

logger = logging.getLogger("sanna.escalation")


# =============================================================================
# CALLBACK REGISTRY
# =============================================================================

_CALLBACK_REGISTRY: dict[str, Callable] = {}


def register_escalation_callback(name: str, handler: Callable) -> None:
    """Register a named callback for use as an escalation target.

    Args:
        name: Unique name matching the ``handler`` field in constitution YAML.
        handler: Callable that receives an ``event_details`` dict.
    """
    _CALLBACK_REGISTRY[name] = handler


def clear_escalation_callbacks() -> None:
    """Remove all registered escalation callbacks."""
    _CALLBACK_REGISTRY.clear()


def get_escalation_callback(name: str) -> Optional[Callable]:
    """Look up a registered callback by name. Returns None if not found."""
    return _CALLBACK_REGISTRY.get(name)


# =============================================================================
# DATA CLASSES
# =============================================================================

@dataclass
class EscalationTarget:
    """Runtime escalation target resolved from a constitution rule.

    Attributes:
        type: Target type — ``"log"``, ``"webhook"``, or ``"callback"``.
        url: Webhook URL (only for ``type="webhook"``).
        handler: Resolved callback function (only for ``type="callback"``).
    """
    type: str = "log"
    url: Optional[str] = None
    handler: Optional[Callable] = None


@dataclass
class EscalationResult:
    """Result of executing an escalation action.

    Attributes:
        success: Whether the escalation completed without error.
        target_type: The type of target that was executed.
        details: Structured details about the escalation (log entry, webhook
            response, callback result, or error information).
    """
    success: bool
    target_type: str
    details: dict


# =============================================================================
# EXECUTION
# =============================================================================

def execute_escalation(
    target: EscalationTarget,
    event_details: dict,
) -> EscalationResult:
    """Execute an escalation action against the given target.

    Dispatches to the appropriate handler based on ``target.type``:

    - ``"log"``: Writes to Python logging and returns structured entry.
    - ``"webhook"``: POSTs JSON payload to ``target.url`` via httpx.
    - ``"callback"``: Calls ``target.handler(event_details)``.

    Falls back to log on missing URL/handler. Webhook and callback
    errors return ``success=False`` without log fallback.

    Args:
        target: The resolved escalation target.
        event_details: Dict describing the escalation event (action name,
            params, decision reason, etc.).

    Returns:
        EscalationResult with success status and structured details.
    """
    timestamp = datetime.now(timezone.utc).isoformat()

    if target.type == "webhook":
        return _execute_webhook(target, event_details, timestamp)
    elif target.type == "callback":
        return _execute_callback(target, event_details, timestamp)
    else:
        return _execute_log(event_details, timestamp)


def _execute_log(event_details: dict, timestamp: str) -> EscalationResult:
    """Log escalation — write to Python logger and return structured entry."""
    log_entry = {
        "timestamp": timestamp,
        "type": "escalation",
        **event_details,
    }
    logger.warning("Escalation event: %s", log_entry)
    return EscalationResult(success=True, target_type="log", details=log_entry)


def _validate_escalation_url(url: str) -> Optional[str]:
    """Validate webhook URL against SSRF, returning error string or None."""
    try:
        from sanna.gateway.config import validate_webhook_url
        validate_webhook_url(url)
        return None
    except Exception as e:
        return str(e)


def _execute_webhook(
    target: EscalationTarget,
    event_details: dict,
    timestamp: str,
) -> EscalationResult:
    """Webhook escalation — POST JSON to target URL."""
    if not target.url:
        logger.warning("Webhook escalation target has no URL, falling back to log")
        return _execute_log(event_details, timestamp)

    url_error = _validate_escalation_url(target.url)
    if url_error:
        logger.error("Webhook URL rejected by SSRF validation: %s", url_error)
        return EscalationResult(
            success=False,
            target_type="webhook",
            details={"url": target.url, "error": f"URL validation failed: {url_error}"},
        )

    try:
        import httpx
    except ImportError:
        return EscalationResult(
            success=False,
            target_type="webhook",
            details={"url": target.url, "error": "httpx is not installed. Install it with: pip install httpx"},
        )

    payload = {
        "timestamp": timestamp,
        "type": "escalation",
        **event_details,
    }
    try:
        with httpx.Client(timeout=10.0, follow_redirects=False) as client:
            resp = client.post(target.url, json=payload)
            resp.raise_for_status()
        return EscalationResult(
            success=True,
            target_type="webhook",
            details={
                "url": target.url,
                "status_code": resp.status_code,
                "payload": payload,
            },
        )
    except Exception as e:
        logger.error("Webhook escalation failed: %s", e)
        return EscalationResult(
            success=False,
            target_type="webhook",
            details={"url": target.url, "error": str(e), "payload": payload},
        )


def _execute_callback(
    target: EscalationTarget,
    event_details: dict,
    timestamp: str,
) -> EscalationResult:
    """Callback escalation — invoke registered handler function."""
    handler = target.handler
    if handler is None:
        logger.warning("Callback escalation target has no handler, falling back to log")
        return _execute_log(event_details, timestamp)

    try:
        result = handler(event_details)
        return EscalationResult(
            success=True,
            target_type="callback",
            details={"callback_result": result, "event": event_details},
        )
    except Exception as e:
        logger.error("Callback escalation failed: %s", e)
        return EscalationResult(
            success=False,
            target_type="callback",
            details={"error": str(e), "event": event_details},
        )


# =============================================================================
# ASYNC EXECUTION (Block G)
# =============================================================================

async def async_execute_escalation(
    target: EscalationTarget,
    event_details: dict,
) -> EscalationResult:
    """Execute an escalation action asynchronously.

    For ``"webhook"`` targets, uses ``httpx.AsyncClient`` when available,
    falling back to a background thread with ``urllib.request`` if httpx
    is not installed.  Log and callback targets delegate to their
    synchronous implementations (already non-blocking).
    """
    timestamp = datetime.now(timezone.utc).isoformat()

    if target.type == "webhook":
        return await _execute_webhook_async(target, event_details, timestamp)
    elif target.type == "callback":
        return _execute_callback(target, event_details, timestamp)
    else:
        return _execute_log(event_details, timestamp)


async def _execute_webhook_async(
    target: EscalationTarget,
    event_details: dict,
    timestamp: str,
    timeout: float = 5.0,
) -> EscalationResult:
    """Async webhook escalation — POST JSON via httpx.AsyncClient.

    Falls back to a background thread with ``urllib.request`` when
    httpx is not available.
    """
    if not target.url:
        logger.warning(
            "Webhook escalation target has no URL, falling back to log",
        )
        return _execute_log(event_details, timestamp)

    url_error = _validate_escalation_url(target.url)
    if url_error:
        logger.error("Webhook URL rejected by SSRF validation: %s", url_error)
        return EscalationResult(
            success=False,
            target_type="webhook",
            details={"url": target.url, "error": f"URL validation failed: {url_error}"},
        )

    payload = {
        "timestamp": timestamp,
        "type": "escalation",
        **event_details,
    }

    try:
        import httpx
    except ImportError:
        # Fallback: fire-and-forget via background thread
        return _webhook_threaded_fallback(target.url, payload, timeout)

    try:
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=False) as client:
            resp = await client.post(target.url, json=payload)
            resp.raise_for_status()
        return EscalationResult(
            success=True,
            target_type="webhook",
            details={
                "url": target.url,
                "status_code": resp.status_code,
                "payload": payload,
                "async": True,
            },
        )
    except Exception as e:
        if "Timeout" in type(e).__name__:
            logger.warning("Escalation webhook timed out: %s", target.url)
        else:
            logger.warning(
                "Escalation webhook failed: %s — %s", target.url, e,
            )
        return EscalationResult(
            success=False,
            target_type="webhook",
            details={
                "url": target.url,
                "error": str(e),
                "payload": payload,
                "async": True,
            },
        )


def _webhook_threaded_fallback(
    url: str,
    payload: dict,
    timeout: float = 5.0,
) -> EscalationResult:
    """Send webhook via a background daemon thread when httpx is unavailable.

    Uses ``urllib.request`` from the standard library.  The thread is
    daemonic so it won't block process exit.  Installs a redirect-blocking
    handler to prevent token leakage via open-redirect attacks.
    """
    import json as _json
    import threading
    import urllib.error
    import urllib.request

    def _send() -> None:
        try:
            # Re-validate URL at send time to prevent DNS rebinding
            url_error = _validate_escalation_url(url)
            if url_error:
                logger.warning(
                    "Threaded webhook fallback URL rejected: %s — %s", url, url_error,
                )
                return

            class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
                """Reject ALL HTTP redirects (301, 302, 303, 307, 308)."""

                def redirect_request(
                    self, req, fp, code, msg, headers, newurl,
                ):
                    logger.warning(
                        "Escalation webhook redirect (%d) to %s — blocked.",
                        code,
                        newurl,
                    )
                    raise urllib.error.HTTPError(
                        req.full_url,
                        code,
                        f"Redirect to {newurl} blocked by security policy",
                        headers,
                        fp,
                    )

            opener = urllib.request.build_opener(_NoRedirectHandler)
            data = _json.dumps(payload).encode()
            req = urllib.request.Request(
                url,
                data=data,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            opener.open(req, timeout=timeout)
        except Exception as exc:
            logger.warning(
                "Threaded webhook fallback failed: %s — %s", url, exc,
            )

    threading.Thread(target=_send, daemon=True).start()
    return EscalationResult(
        success=True,
        target_type="webhook",
        details={
            "url": url,
            "payload": payload,
            "async": True,
            "method": "threaded_fallback",
        },
    )
