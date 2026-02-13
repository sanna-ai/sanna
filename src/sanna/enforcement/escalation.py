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


def _execute_webhook(
    target: EscalationTarget,
    event_details: dict,
    timestamp: str,
) -> EscalationResult:
    """Webhook escalation — POST JSON to target URL."""
    if not target.url:
        logger.warning("Webhook escalation target has no URL, falling back to log")
        return _execute_log(event_details, timestamp)

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
        with httpx.Client(timeout=10.0) as client:
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
