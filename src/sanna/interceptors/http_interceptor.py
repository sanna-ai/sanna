"""HTTP interceptor — patches Python HTTP libraries at runtime.

Enforces governance on HTTP/API invocations by intercepting calls to
requests, httpx, urllib.request, and urllib3.

Each intercepted call:
1. Extracts HTTP method and URL
2. Evaluates against constitution api_permissions
3. Computes receipt triad (input_hash, reasoning_hash, action_hash)
4. Generates and persists a governance receipt
5. Either allows, halts (ConnectionError), or escalates (PermissionError)
"""

from __future__ import annotations

import fnmatch
import hashlib
import json as _json
import logging
import uuid
from dataclasses import asdict
from datetime import datetime, timezone
from typing import Optional

from ..constitution import load_constitution, constitution_to_receipt_ref
from ..hashing import hash_obj, hash_text, EMPTY_HASH
from ..receipt import generate_receipt, receipt_to_dict
from ..sinks.sink import ReceiptSink
from .api_authority import evaluate_api_authority, check_api_invariants, ApiAuthorityDecision

logger = logging.getLogger("sanna.interceptor.http")

_MODE_TO_ENFORCEMENT_LEVEL = {
    "enforce": "halt",
    "audit": "warn",
    "passthrough": "log",
}


# =============================================================================
# MODULE STATE
# =============================================================================

_http_state: dict = {}
_originals: dict = {}
_patched: bool = False

# Default URL exclusions (prevent infinite recursion with CloudHTTPSink)
_DEFAULT_EXCLUSIONS = [
    "https://api.sanna.cloud/*",
    "https://*.sanna.cloud/*",
]


# =============================================================================
# PUBLIC API
# =============================================================================

def patch_http(
    constitution_path: str,
    sink: ReceiptSink,
    agent_id: str,
    mode: str = "enforce",
    signing_key: Optional[bytes] = None,
    content_mode: Optional[str] = None,
    workflow_id: Optional[str] = None,
    parent_fingerprint: Optional[str] = None,
    exclude_urls: Optional[list] = None,
) -> None:
    """Patch Python HTTP libraries to enforce governance.

    Args:
        constitution_path: Path to the constitution YAML/JSON file.
        sink: ReceiptSink implementation for persisting receipts.
        agent_id: Agent identifier for receipts.
        mode: Enforcement mode — "enforce", "audit", or "passthrough".
        signing_key: Optional Ed25519 private key bytes for receipt signing.
        content_mode: Optional content mode attestation.
        workflow_id: Optional workflow identifier for receipt chaining.
        parent_fingerprint: Optional parent receipt fingerprint for chaining.
        exclude_urls: Optional list of URL glob patterns to skip interception.
            Default Sanna Cloud exclusions are always appended.
    """
    global _patched

    if _patched:
        return

    if mode not in ("enforce", "audit", "passthrough"):
        raise ValueError(f"Invalid mode: {mode!r}. Must be 'enforce', 'audit', or 'passthrough'.")

    constitution = load_constitution(constitution_path)

    # Build exclusion list: user exclusions + defaults
    all_exclusions = list(exclude_urls or [])
    all_exclusions.extend(_DEFAULT_EXCLUSIONS)

    _http_state.update({
        "constitution": constitution,
        "constitution_path": constitution_path,
        "sink": sink,
        "agent_id": agent_id,
        "mode": mode,
        "signing_key": signing_key,
        "content_mode": content_mode,
        "workflow_id": workflow_id,
        "parent_fingerprint": parent_fingerprint,
        "exclude_urls": all_exclusions,
        "agent_session_id": None,
    })

    # Patch requests (if installed)
    try:
        import requests
        _originals["requests.request"] = requests.request
        _originals["requests.get"] = requests.get
        _originals["requests.post"] = requests.post
        _originals["requests.put"] = requests.put
        _originals["requests.patch"] = requests.patch
        _originals["requests.delete"] = requests.delete
        _originals["requests.head"] = requests.head
        _originals["requests.options"] = requests.options
        _originals["requests.Session.request"] = requests.Session.request

        requests.request = _patched_requests_request
        requests.get = _make_patched_convenience("GET")
        requests.post = _make_patched_convenience("POST")
        requests.put = _make_patched_convenience("PUT")
        requests.patch = _make_patched_convenience("PATCH")
        requests.delete = _make_patched_convenience("DELETE")
        requests.head = _make_patched_convenience("HEAD")
        requests.options = _make_patched_convenience("OPTIONS")
        requests.Session.request = _patched_session_request
    except ImportError:
        pass

    # Patch httpx (if installed)
    try:
        import httpx
        _originals["httpx.Client.request"] = httpx.Client.request
        _originals["httpx.AsyncClient.request"] = httpx.AsyncClient.request

        httpx.Client.request = _patched_httpx_sync_request
        httpx.AsyncClient.request = _patched_httpx_async_request
    except ImportError:
        pass

    # Patch urllib.request (stdlib)
    import urllib.request
    _originals["urllib.request.urlopen"] = urllib.request.urlopen
    urllib.request.urlopen = _patched_urlopen

    # Patch urllib3 (if installed)
    try:
        import urllib3
        _originals["urllib3.PoolManager.urlopen"] = urllib3.PoolManager.urlopen
        urllib3.PoolManager.urlopen = _patched_urllib3_urlopen
    except ImportError:
        pass

    _patched = True

    # SAN-206: emit session_manifest for the HTTP surface. Mode-aware
    # fail-closed/fail-open per open-beta governance posture.
    try:
        _emit_http_session_manifest()
    except Exception as exc:
        if mode == "enforce":
            _patched = False
            unpatch_http()
            raise RuntimeError(
                f"sanna HTTP interceptor: failed to emit session_manifest "
                f"receipt in enforce mode; refusing to start. Cause: {exc}"
            ) from exc
        else:
            logger.warning(
                "sanna HTTP interceptor: session_manifest emission failed in "
                "%s mode; continuing without manifest. Cause: %s",
                mode,
                exc,
            )


def unpatch_http() -> None:
    """Restore all original HTTP library functions."""
    global _patched

    if not _patched:
        return

    # Restore requests
    if "requests.request" in _originals:
        try:
            import requests
            requests.request = _originals["requests.request"]
            requests.get = _originals["requests.get"]
            requests.post = _originals["requests.post"]
            requests.put = _originals["requests.put"]
            requests.patch = _originals["requests.patch"]
            requests.delete = _originals["requests.delete"]
            requests.head = _originals["requests.head"]
            requests.options = _originals["requests.options"]
            requests.Session.request = _originals["requests.Session.request"]
        except ImportError:
            pass

    # Restore httpx
    if "httpx.Client.request" in _originals:
        try:
            import httpx
            httpx.Client.request = _originals["httpx.Client.request"]
            httpx.AsyncClient.request = _originals["httpx.AsyncClient.request"]
        except ImportError:
            pass

    # Restore urllib.request
    if "urllib.request.urlopen" in _originals:
        import urllib.request
        urllib.request.urlopen = _originals["urllib.request.urlopen"]

    # Restore urllib3
    if "urllib3.PoolManager.urlopen" in _originals:
        try:
            import urllib3
            urllib3.PoolManager.urlopen = _originals["urllib3.PoolManager.urlopen"]
        except ImportError:
            pass

    _originals.clear()
    _http_state.clear()
    _patched = False


# =============================================================================
# URL EXCLUSION
# =============================================================================

def _is_excluded(url: str) -> bool:
    """Check if URL matches any exclusion pattern."""
    for pattern in _http_state.get("exclude_urls", []):
        if fnmatch.fnmatch(url, pattern):
            return True
    return False


# =============================================================================
# HASH COMPUTATION
# =============================================================================

def _compute_body_hash(kwargs: dict) -> str:
    """Compute SHA-256 hash of request body."""
    body = kwargs.get("data") or kwargs.get("json")
    if body is None:
        return EMPTY_HASH

    if kwargs.get("json") is not None:
        body_bytes = _json.dumps(body, separators=(",", ":"), sort_keys=True).encode("utf-8")
    elif isinstance(body, str):
        body_bytes = body.encode("utf-8")
    elif isinstance(body, bytes):
        body_bytes = body
    else:
        body_bytes = str(body).encode("utf-8")

    return hashlib.sha256(body_bytes).hexdigest()


def _compute_input_hash(method: str, url: str, kwargs: dict) -> str:
    """Compute input_hash per protocol v1.2 Section 7.7.

    Canonical JSON key order (alphabetical): body_hash, headers_keys, method, url.
    """
    body_hash = _compute_body_hash(kwargs)
    headers = kwargs.get("headers", {})
    headers_keys = sorted(headers.keys()) if headers else []

    input_obj = {
        "body_hash": body_hash,
        "headers_keys": headers_keys,
        "method": method,
        "url": url,
    }
    return hash_obj(input_obj)


def _compute_action_hash_from_response(status_code, resp_headers, resp_body):
    """Compute action_hash from HTTP response."""
    resp_headers_keys = sorted(resp_headers.keys()) if resp_headers else []

    if resp_body is not None:
        if isinstance(resp_body, bytes):
            resp_body_hash = hashlib.sha256(resp_body).hexdigest()
        else:
            resp_body_hash = hashlib.sha256(str(resp_body).encode("utf-8")).hexdigest()
    else:
        resp_body_hash = EMPTY_HASH

    action_obj = {
        "body_hash": resp_body_hash,
        "response_headers_keys": resp_headers_keys,
        "status_code": status_code,
    }
    return hash_obj(action_obj)


def _halted_action_hash() -> str:
    """Compute action_hash for a halted request (no response)."""
    action_obj = {
        "body_hash": EMPTY_HASH,
        "response_headers_keys": [],
        "status_code": None,
    }
    return hash_obj(action_obj)


# =============================================================================
# RECEIPT EMISSION
# =============================================================================

def _emit_http_receipt(
    *,
    event_type: str,
    context_limitation: str,
    input_hash: str,
    reasoning_hash: str,
    action_hash: str,
    decision: ApiAuthorityDecision,
    url: str,
    method: str,
    justification: Optional[str],
) -> Optional[str]:
    """Generate and persist an HTTP governance receipt.

    Returns the receipt fingerprint on success, None on failure.
    """
    correlation_id = f"http-{method.lower()}-{uuid.uuid4()}"

    inputs = {
        "query": f"{method} {url}",
        "context": justification or None,
    }
    outputs = {
        "response": f"decision={decision.decision}, reason={decision.reason}",
    }

    # Map decision to enforcement action
    action_map = {
        "halt": "halted",
        "escalate": "escalated",
        "allow": "allowed",
    }
    enforcement_action = action_map.get(decision.decision, "allowed")

    if _http_state["mode"] == "audit" and decision.decision in ("halt", "escalate"):
        enforcement_action = "warned"

    enforcement_dict = {
        "action": enforcement_action,
        "reason": decision.reason,
        "failed_checks": [],
        "enforcement_mode": _MODE_TO_ENFORCEMENT_LEVEL.get(_http_state["mode"], "halt"),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    constitution_ref = None
    try:
        constitution_ref = constitution_to_receipt_ref(_http_state["constitution"])
    except Exception:  # Broad catch: constitution_ref is optional metadata
        logger.debug("Could not build constitution_ref", exc_info=True)

    receipt_extensions = {
        "com.sanna.interceptor": {
            "surface": "api",
            "url": url,
            "method": method,
            "rule_id": decision.rule_id,
            "input_hash": input_hash,
            "reasoning_hash": reasoning_hash,
            "action_hash": action_hash,
        },
    }

    trace_data = {
        "correlation_id": correlation_id,
        "observations": [],
        "output": {"final_answer": outputs["response"]},
        "input": inputs.get("query", ""),
        "metadata": {},
    }

    if _http_state.get("agent_session_id") is None:
        import uuid as _uuid
        _http_state["agent_session_id"] = _uuid.uuid4().hex

    agent_identity_dict = {"agent_session_id": _http_state["agent_session_id"]}

    receipt = generate_receipt(
        trace_data=trace_data,
        constitution_ref_override=constitution_ref,
        parent_receipts=[_http_state["parent_fingerprint"]] if _http_state.get("parent_fingerprint") else None,
        workflow_id=_http_state.get("workflow_id"),
        content_mode=_http_state.get("content_mode"),
        event_type=event_type,
        context_limitation=context_limitation,
        skip_default_checks=True,
        enforcement=enforcement_dict,
        enforcement_surface="http_interceptor",
        invariants_scope="authority_only",
        agent_identity=agent_identity_dict,
    )

    receipt_dict = receipt_to_dict(receipt)
    receipt_dict["enforcement"] = enforcement_dict
    receipt_dict["extensions"] = receipt_extensions
    receipt_dict["input_hash"] = input_hash
    receipt_dict["reasoning_hash"] = reasoning_hash
    receipt_dict["action_hash"] = action_hash
    receipt_dict["event_type"] = event_type
    receipt_dict["context_limitation"] = context_limitation

    try:
        result = _http_state["sink"].store(receipt_dict)
        if not result.ok:
            logger.warning("Receipt sink reported failures: %s", result.errors)
    except Exception:  # Broad catch: sink persistence must not block intercepted operation
        logger.warning("Failed to persist HTTP receipt", exc_info=True)

    return receipt.receipt_fingerprint


# =============================================================================
# ENFORCEMENT CORE
# =============================================================================

def _enforce_http_call(method: str, url: str, kwargs: dict, justification: Optional[str]):
    """Core enforcement logic shared across all HTTP library patches.

    Returns (decision, input_hash, reasoning_hash) for post-execution receipt.
    Raises ConnectionError or PermissionError in enforce mode on violations.
    """
    method_upper = method.upper()

    input_hash = _compute_input_hash(method_upper, url, kwargs)
    reasoning_hash = hash_text(justification) if justification else EMPTY_HASH

    decision = evaluate_api_authority(method_upper, url, _http_state["constitution"])

    # Check invariants (may override allow)
    inv = check_api_invariants(url, _http_state["constitution"])
    if inv is not None and inv.verdict == "halt":
        decision = ApiAuthorityDecision(
            decision="halt",
            reason=f"Invariant {inv.id}: {inv.description}",
            rule_id=inv.id,
        )

    ctx_limit = "api_no_justification" if not justification else "api_execution"

    if decision.decision == "halt" and _http_state["mode"] == "enforce":
        # SAN-397: substitute api_invocation_anomaly for suppressed endpoints
        # when constitution opts in via anomaly_tracking.http
        constitution = _http_state.get("constitution")
        ab = getattr(constitution, "authority_boundaries", None) if constitution else None
        anomaly_tracking = getattr(ab, "anomaly_tracking", None) if ab else None
        if anomaly_tracking is not None and anomaly_tracking.http and _http_state.get("manifest_full_fingerprint"):
            matched_pattern = next(
                (p for p in _http_state.get("suppressed_patterns", set())
                 if fnmatch.fnmatch(url, p)),
                None,
            )
            if matched_pattern is not None:
                _emit_http_invocation_anomaly(matched_pattern)
                raise ConnectionError(f"Connection refused: {url}")

        action_hash = _halted_action_hash()
        _emit_http_receipt(
            event_type="api_invocation_halted",
            context_limitation=ctx_limit,
            input_hash=input_hash,
            reasoning_hash=reasoning_hash,
            action_hash=action_hash,
            decision=decision,
            url=url,
            method=method_upper,
            justification=justification,
        )
        raise ConnectionError(f"Connection refused: {url}")

    if decision.decision == "escalate" and _http_state["mode"] == "enforce":
        action_hash = _halted_action_hash()
        _emit_http_receipt(
            event_type="api_invocation_escalated",
            context_limitation=ctx_limit,
            input_hash=input_hash,
            reasoning_hash=reasoning_hash,
            action_hash=action_hash,
            decision=decision,
            url=url,
            method=method_upper,
            justification=justification,
        )
        raise PermissionError(f"Escalation required: {decision.reason}")

    return decision, input_hash, reasoning_hash, method_upper


def _emit_post_execution_receipt(
    decision, input_hash, reasoning_hash, method_upper, url,
    justification, status_code, resp_headers, resp_body,
):
    """Emit receipt after successful HTTP execution."""
    action_hash = _compute_action_hash_from_response(status_code, resp_headers, resp_body)
    ctx_limit = "api_no_justification" if not justification else "api_execution"

    mode = _http_state["mode"]
    if mode == "audit" and decision.decision == "halt":
        event_type = "api_invocation_halted"
    elif mode == "audit" and decision.decision == "escalate":
        event_type = "api_invocation_escalated"
    else:
        event_type = "api_invocation_allowed"

    _emit_http_receipt(
        event_type=event_type,
        context_limitation=ctx_limit,
        input_hash=input_hash,
        reasoning_hash=reasoning_hash,
        action_hash=action_hash,
        decision=decision,
        url=url,
        method=method_upper,
        justification=justification,
    )


# =============================================================================
# PATCHED: requests.request
# =============================================================================

def _patched_requests_request(method, url, **kwargs):
    """Intercepted requests.request with governance enforcement."""
    justification = kwargs.pop("justification", None)

    if _is_excluded(str(url)):
        return _originals["requests.request"](method, url, **kwargs)

    decision, input_hash, reasoning_hash, method_upper = _enforce_http_call(
        method, str(url), kwargs, justification,
    )

    response = _originals["requests.request"](method, url, **kwargs)

    _emit_post_execution_receipt(
        decision, input_hash, reasoning_hash, method_upper, str(url),
        justification, response.status_code, response.headers, response.content,
    )

    return response


# =============================================================================
# PATCHED: requests convenience functions
# =============================================================================

def _make_patched_convenience(http_method: str):
    """Create a patched convenience function (get, post, etc.)."""
    def _patched(url, **kwargs):
        justification = kwargs.pop("justification", None)

        if _is_excluded(str(url)):
            return _originals[f"requests.{http_method.lower()}"](url, **kwargs)

        decision, input_hash, reasoning_hash, method_upper = _enforce_http_call(
            http_method, str(url), kwargs, justification,
        )

        response = _originals[f"requests.{http_method.lower()}"](url, **kwargs)

        _emit_post_execution_receipt(
            decision, input_hash, reasoning_hash, method_upper, str(url),
            justification, response.status_code, response.headers, response.content,
        )

        return response

    _patched.__name__ = http_method.lower()
    _patched.__qualname__ = f"_patched_{http_method.lower()}"
    return _patched


# =============================================================================
# PATCHED: requests.Session.request
# =============================================================================

def _patched_session_request(self, method, url, **kwargs):
    """Intercepted requests.Session.request with governance enforcement."""
    justification = kwargs.pop("justification", None)

    if _is_excluded(str(url)):
        return _originals["requests.Session.request"](self, method, url, **kwargs)

    decision, input_hash, reasoning_hash, method_upper = _enforce_http_call(
        method, str(url), kwargs, justification,
    )

    response = _originals["requests.Session.request"](self, method, url, **kwargs)

    _emit_post_execution_receipt(
        decision, input_hash, reasoning_hash, method_upper, str(url),
        justification, response.status_code, response.headers, response.content,
    )

    return response


# =============================================================================
# PATCHED: httpx.Client.request (sync)
# =============================================================================

def _patched_httpx_sync_request(self, method, url, **kwargs):
    """Intercepted httpx.Client.request (sync) with governance enforcement."""
    justification = kwargs.pop("justification", None)

    if _is_excluded(str(url)):
        return _originals["httpx.Client.request"](self, method, url, **kwargs)

    decision, input_hash, reasoning_hash, method_upper = _enforce_http_call(
        method, str(url), kwargs, justification,
    )

    response = _originals["httpx.Client.request"](self, method, url, **kwargs)

    _emit_post_execution_receipt(
        decision, input_hash, reasoning_hash, method_upper, str(url),
        justification, response.status_code, response.headers, response.content,
    )

    return response


# =============================================================================
# PATCHED: httpx.AsyncClient.request (async)
# =============================================================================

async def _patched_httpx_async_request(self, method, url, **kwargs):
    """Intercepted httpx.AsyncClient.request (async) with governance enforcement."""
    justification = kwargs.pop("justification", None)

    if _is_excluded(str(url)):
        return await _originals["httpx.AsyncClient.request"](self, method, url, **kwargs)

    decision, input_hash, reasoning_hash, method_upper = _enforce_http_call(
        method, str(url), kwargs, justification,
    )

    response = await _originals["httpx.AsyncClient.request"](self, method, url, **kwargs)

    _emit_post_execution_receipt(
        decision, input_hash, reasoning_hash, method_upper, str(url),
        justification, response.status_code, response.headers, response.content,
    )

    return response


# =============================================================================
# PATCHED: urllib.request.urlopen
# =============================================================================

def _patched_urlopen(url, data=None, timeout=None, **kwargs):
    """Intercepted urllib.request.urlopen with governance enforcement."""
    import urllib.request

    # Extract URL string
    if isinstance(url, str):
        url_str = url
        method = "POST" if data is not None else "GET"
    else:
        # urllib.request.Request object
        url_str = url.full_url if hasattr(url, "full_url") else str(url)
        method = getattr(url, "method", None) or ("POST" if data is not None else "GET")

    if _is_excluded(url_str):
        call_kwargs = {}
        if data is not None:
            call_kwargs["data"] = data
        if timeout is not None:
            call_kwargs["timeout"] = timeout
        call_kwargs.update(kwargs)
        return _originals["urllib.request.urlopen"](url, **call_kwargs)

    # Build kwargs for hash computation
    hash_kwargs = {}
    if data is not None:
        hash_kwargs["data"] = data

    method_upper = method.upper()
    input_hash = _compute_input_hash(method_upper, url_str, hash_kwargs)
    reasoning_hash = EMPTY_HASH  # urllib has no justification mechanism

    decision = evaluate_api_authority(method_upper, url_str, _http_state["constitution"])

    inv = check_api_invariants(url_str, _http_state["constitution"])
    if inv is not None and inv.verdict == "halt":
        decision = ApiAuthorityDecision(
            decision="halt",
            reason=f"Invariant {inv.id}: {inv.description}",
            rule_id=inv.id,
        )

    ctx_limit = "api_no_justification"

    if decision.decision == "halt" and _http_state["mode"] == "enforce":
        action_hash = _halted_action_hash()
        _emit_http_receipt(
            event_type="api_invocation_halted",
            context_limitation=ctx_limit,
            input_hash=input_hash,
            reasoning_hash=reasoning_hash,
            action_hash=action_hash,
            decision=decision,
            url=url_str,
            method=method_upper,
            justification=None,
        )
        raise ConnectionError(f"Connection refused: {url_str}")

    if decision.decision == "escalate" and _http_state["mode"] == "enforce":
        action_hash = _halted_action_hash()
        _emit_http_receipt(
            event_type="api_invocation_escalated",
            context_limitation=ctx_limit,
            input_hash=input_hash,
            reasoning_hash=reasoning_hash,
            action_hash=action_hash,
            decision=decision,
            url=url_str,
            method=method_upper,
            justification=None,
        )
        raise PermissionError(f"Escalation required: {decision.reason}")

    # Execute
    call_kwargs = {}
    if data is not None:
        call_kwargs["data"] = data
    if timeout is not None:
        call_kwargs["timeout"] = timeout
    call_kwargs.update(kwargs)
    response = _originals["urllib.request.urlopen"](url, **call_kwargs)

    # urllib response: read content for hashing, then seek back if possible
    resp_body = response.read()
    resp_headers = dict(response.headers) if hasattr(response, "headers") else {}
    status_code = getattr(response, "status", getattr(response, "code", None))

    action_hash = _compute_action_hash_from_response(status_code, resp_headers, resp_body)

    mode = _http_state["mode"]
    if mode == "audit" and decision.decision == "halt":
        event_type = "api_invocation_halted"
    elif mode == "audit" and decision.decision == "escalate":
        event_type = "api_invocation_escalated"
    else:
        event_type = "api_invocation_allowed"

    _emit_http_receipt(
        event_type=event_type,
        context_limitation=ctx_limit,
        input_hash=input_hash,
        reasoning_hash=reasoning_hash,
        action_hash=action_hash,
        decision=decision,
        url=url_str,
        method=method_upper,
        justification=None,
    )

    # Wrap response so read() still works for the caller
    import io

    class _ReadableResponse:
        """Wrapper that replays already-read content."""
        def __init__(self, original, content):
            self._original = original
            self._buffer = io.BytesIO(content)
            # Copy attributes
            self.headers = original.headers
            self.status = getattr(original, "status", getattr(original, "code", None))
            self.code = self.status
            self.url = getattr(original, "url", url_str)

        def read(self, amt=None):
            return self._buffer.read(amt)

        def readline(self):
            return self._buffer.readline()

        def readlines(self):
            return self._buffer.readlines()

        def close(self):
            self._original.close()

        def __enter__(self):
            return self

        def __exit__(self, *args):
            self.close()
            return False

        def __getattr__(self, name):
            return getattr(self._original, name)

    return _ReadableResponse(response, resp_body)


# =============================================================================
# PATCHED: urllib3.PoolManager.urlopen
# =============================================================================

def _patched_urllib3_urlopen(self, method, url, **kwargs):
    """Intercepted urllib3.PoolManager.urlopen with governance enforcement."""
    if _is_excluded(str(url)):
        return _originals["urllib3.PoolManager.urlopen"](self, method, url, **kwargs)

    method_upper = method.upper()

    hash_kwargs = {}
    body = kwargs.get("body")
    if body is not None:
        hash_kwargs["data"] = body

    input_hash = _compute_input_hash(method_upper, str(url), hash_kwargs)
    reasoning_hash = EMPTY_HASH

    decision = evaluate_api_authority(method_upper, str(url), _http_state["constitution"])

    inv = check_api_invariants(str(url), _http_state["constitution"])
    if inv is not None and inv.verdict == "halt":
        decision = ApiAuthorityDecision(
            decision="halt",
            reason=f"Invariant {inv.id}: {inv.description}",
            rule_id=inv.id,
        )

    ctx_limit = "api_no_justification"

    if decision.decision == "halt" and _http_state["mode"] == "enforce":
        action_hash = _halted_action_hash()
        _emit_http_receipt(
            event_type="api_invocation_halted",
            context_limitation=ctx_limit,
            input_hash=input_hash,
            reasoning_hash=reasoning_hash,
            action_hash=action_hash,
            decision=decision,
            url=str(url),
            method=method_upper,
            justification=None,
        )
        raise ConnectionError(f"Connection refused: {url}")

    if decision.decision == "escalate" and _http_state["mode"] == "enforce":
        action_hash = _halted_action_hash()
        _emit_http_receipt(
            event_type="api_invocation_escalated",
            context_limitation=ctx_limit,
            input_hash=input_hash,
            reasoning_hash=reasoning_hash,
            action_hash=action_hash,
            decision=decision,
            url=str(url),
            method=method_upper,
            justification=None,
        )
        raise PermissionError(f"Escalation required: {decision.reason}")

    response = _originals["urllib3.PoolManager.urlopen"](self, method, url, **kwargs)

    resp_body = response.data if hasattr(response, "data") else b""
    resp_headers = dict(response.headers) if hasattr(response, "headers") else {}
    status_code = getattr(response, "status", None)

    action_hash = _compute_action_hash_from_response(status_code, resp_headers, resp_body)

    mode = _http_state["mode"]
    if mode == "audit" and decision.decision == "halt":
        event_type = "api_invocation_halted"
    elif mode == "audit" and decision.decision == "escalate":
        event_type = "api_invocation_escalated"
    else:
        event_type = "api_invocation_allowed"

    _emit_http_receipt(
        event_type=event_type,
        context_limitation=ctx_limit,
        input_hash=input_hash,
        reasoning_hash=reasoning_hash,
        action_hash=action_hash,
        decision=decision,
        url=str(url),
        method=method_upper,
        justification=None,
    )

    return response


# =============================================================================
# SESSION MANIFEST EMISSION (SAN-206)
# =============================================================================

def _emit_http_session_manifest() -> None:
    """Emit a session_manifest receipt for the HTTP surface (SAN-206).

    surfaces=['http'], event_type='session_manifest', invariants_scope='none',
    enforcement=null, enforcement_surface='http_interceptor'.
    """
    from ..manifest import generate_manifest
    from ..middleware import generate_constitution_receipt, build_trace_data

    constitution = _http_state["constitution"]
    sink = _http_state["sink"]
    content_mode = _http_state.get("content_mode") or None

    try:
        manifest_ext = generate_manifest(
            constitution,
            surfaces=["http"],
            content_mode=content_mode,
        )
        status_override = "PASS"
        # SAN-397: capture suppressed patterns for anomaly emission
        http_surface = manifest_ext.get("surfaces", {}).get("http", {})
        _http_state["suppressed_patterns"] = set(http_surface.get("patterns_suppressed", []))
    except Exception as exc:
        logger.error("HTTP session_manifest generate_manifest failed: %s", exc)
        manifest_ext = {
            "version": "0.1",
            "composition_basis": "static",
            "surfaces": {},
        }
        status_override = "FAIL"
        _http_state["suppressed_patterns"] = set()

    correlation_id = f"manifest-http-{uuid.uuid4().hex[:12]}"
    trace_data = build_trace_data(
        correlation_id=correlation_id,
        query="session_manifest",
        context="",
        output="",
    )

    constitution_ref = None
    try:
        constitution_ref = constitution_to_receipt_ref(constitution)
    except Exception:
        logger.debug("Could not build constitution_ref for HTTP manifest", exc_info=True)

    receipt = generate_constitution_receipt(
        trace_data,
        check_configs=[],
        custom_records=[],
        constitution_ref=constitution_ref,
        constitution_version=(
            constitution.schema_version if constitution else ""
        ),
        extensions={"com.sanna.manifest": manifest_ext},
        enforcement=None,
        authority_decisions=None,
        enforcement_surface="http_interceptor",
        invariants_scope="none",
    )
    receipt["event_type"] = "session_manifest"
    if status_override == "FAIL":
        receipt["status"] = "FAIL"

    if content_mode:
        receipt["content_mode"] = content_mode
        receipt["content_mode_source"] = "local_config"

    # SAN-397: capture manifest fingerprint for anomaly chaining (before signing)
    _http_state["manifest_full_fingerprint"] = receipt.get("full_fingerprint")

    signing_key = _http_state.get("signing_key")
    if signing_key is not None:
        from ..crypto import sign_receipt_from_pem
        receipt = sign_receipt_from_pem(receipt, signing_key)

    result = sink.store(receipt)
    if not result.ok:
        raise RuntimeError(f"HTTP manifest sink reported failures: {result.errors}")


def _emit_http_invocation_anomaly(endpoint_pattern: str) -> None:
    """Emit api_invocation_anomaly receipt for a suppressed endpoint attempt (SAN-397).

    Mirrors gateway _emit_invocation_anomaly (server.py:2561) and CLI counterpart.
    Extension namespace: com.sanna.anomaly with attempted_endpoint field
    per SAN-395 Section 2.22.2. endpoint_pattern is the matched suppressed URL glob.
    """
    from ..middleware import generate_constitution_receipt, build_trace_data
    from ..receipt import HaltEvent

    constitution = _http_state["constitution"]
    sink = _http_state["sink"]
    content_mode = _http_state.get("content_mode") or None

    # Ensure agent_session_id is set (mirrors _emit_http_receipt lazy init)
    if _http_state.get("agent_session_id") is None:
        _http_state["agent_session_id"] = uuid.uuid4().hex

    correlation_id = f"anomaly-http-{uuid.uuid4().hex[:12]}"
    trace_data = build_trace_data(
        correlation_id=correlation_id,
        query=f"http endpoint={endpoint_pattern}",
        context="",
        output="",
    )

    constitution_ref = None
    try:
        constitution_ref = constitution_to_receipt_ref(constitution)
    except Exception:
        logger.debug("Could not build constitution_ref for api_invocation_anomaly", exc_info=True)

    enforcement_obj = HaltEvent(
        halted=True,
        reason="endpoint_suppressed_by_constitution",
        failed_checks=[],
        enforcement_mode="halt",
        timestamp=datetime.now(timezone.utc).isoformat(),
    )

    receipt = generate_constitution_receipt(
        trace_data,
        check_configs=[],
        custom_records=[],
        constitution_ref=constitution_ref,
        constitution_version=(
            constitution.schema_version if constitution else ""
        ),
        extensions={
            "com.sanna.anomaly": {
                "attempted_endpoint": endpoint_pattern,
                "suppression_basis": "session_manifest",
            },
        },
        enforcement=enforcement_obj,
        authority_decisions=None,
        enforcement_surface="http_interceptor",
        invariants_scope="authority_only",
        parent_receipts=[_http_state["manifest_full_fingerprint"]],
    )
    receipt["event_type"] = "api_invocation_anomaly"
    receipt["status"] = "FAIL"

    # content_mode on envelope only (Section 2.22.5 field-level redaction is
    # spec-ahead-of-impl; consistent with gateway server.py:2508 + SAN-397 scope)
    if content_mode:
        receipt["content_mode"] = content_mode
        receipt["content_mode_source"] = "local_config"

    receipt["agent_identity"] = {"agent_session_id": _http_state["agent_session_id"]}

    signing_key = _http_state.get("signing_key")
    if signing_key is not None:
        from ..crypto import sign_receipt_from_pem
        receipt = sign_receipt_from_pem(receipt, signing_key)

    try:
        sink.store(receipt)
    except Exception as exc:
        logger.error("api_invocation_anomaly receipt persistence failed: %s", exc)
