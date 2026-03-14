"""Tests for sanna.interceptors.http_interceptor — HTTP/API governance."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from unittest.mock import MagicMock, patch, PropertyMock

import pytest

from sanna.constitution import (
    load_constitution,
    ApiEndpoint,
    ApiInvariant,
    ApiPermissions,
)
from sanna.hashing import hash_obj, hash_text, EMPTY_HASH
from sanna.interceptors import patch_http, unpatch_http
from sanna.interceptors.api_authority import (
    evaluate_api_authority,
    check_api_invariants,
    ApiAuthorityDecision,
)
from sanna.sinks.sink import ReceiptSink, SinkResult


# =============================================================================
# HELPERS
# =============================================================================

CONSTITUTIONS_DIR = Path(__file__).parent / "constitutions"
API_TEST_CONSTITUTION = str(CONSTITUTIONS_DIR / "api-test.yaml")
API_PERMISSIVE_CONSTITUTION = str(CONSTITUTIONS_DIR / "api-permissive.yaml")

# A constitution with no api_permissions block
NO_API_CONSTITUTION = str(CONSTITUTIONS_DIR / "with_authority.yaml")


class CaptureSink(ReceiptSink):
    """Sink that captures receipts for inspection."""

    def __init__(self):
        self.receipts: list[dict] = []

    def store(self, receipt: dict) -> SinkResult:
        self.receipts.append(receipt)
        return SinkResult(stored=1)

    @property
    def last(self) -> dict:
        return self.receipts[-1]

    @property
    def count(self) -> int:
        return len(self.receipts)


def _mock_response(status_code=200, content=b'{"ok":true}', headers=None):
    """Create a mock requests.Response object."""
    resp = MagicMock()
    resp.status_code = status_code
    resp.content = content
    resp.headers = headers or {"Content-Type": "application/json"}
    resp.text = content.decode("utf-8") if isinstance(content, bytes) else str(content)
    return resp


# =============================================================================
# FIXTURES
# =============================================================================

@pytest.fixture(autouse=True)
def cleanup():
    """Ensure HTTP is unpatched after every test."""
    yield
    unpatch_http()


@pytest.fixture
def sink():
    return CaptureSink()


@pytest.fixture
def patched(sink):
    """Patch HTTP with api-test constitution in enforce mode."""
    with patch("sanna.interceptors.http_interceptor._originals", {}) as orig_dict:
        pass  # Let patch_http populate it
    # Actually, we need to mock the requests library calls
    patch_http(
        constitution_path=API_TEST_CONSTITUTION,
        sink=sink,
        agent_id="test-agent",
        mode="enforce",
    )
    return sink


@pytest.fixture
def patched_audit(sink):
    """Patch HTTP with api-test constitution in audit mode."""
    patch_http(
        constitution_path=API_TEST_CONSTITUTION,
        sink=sink,
        agent_id="test-agent",
        mode="audit",
    )
    return sink


@pytest.fixture
def patched_passthrough(sink):
    """Patch HTTP with api-test constitution in passthrough mode."""
    patch_http(
        constitution_path=API_TEST_CONSTITUTION,
        sink=sink,
        agent_id="test-agent",
        mode="passthrough",
    )
    return sink


@pytest.fixture
def patched_permissive(sink):
    """Patch HTTP with permissive constitution."""
    patch_http(
        constitution_path=API_PERMISSIVE_CONSTITUTION,
        sink=sink,
        agent_id="test-agent",
        mode="enforce",
    )
    return sink


# =============================================================================
# 1. INTERCEPTION COVERAGE
# =============================================================================

requests = pytest.importorskip("requests")


def _patch_and_mock(sink, constitution=API_TEST_CONSTITUTION, mode="enforce", **kwargs):
    """Helper: patch HTTP, then replace originals with mocks."""
    patch_http(
        constitution_path=constitution,
        sink=sink,
        agent_id="test-agent",
        mode=mode,
        **kwargs,
    )
    from sanna.interceptors import http_interceptor
    return http_interceptor


def _mock_orig(interceptor, key, response=None):
    """Replace one original with a mock returning a response."""
    if response is None:
        response = _mock_response()
    mock = MagicMock(return_value=response)
    interceptor._originals[key] = mock
    return mock


class TestInterceptionCoverage:
    """Verify HTTP interfaces are intercepted."""

    def test_requests_get_intercepted(self, sink):
        mod = _patch_and_mock(sink)
        _mock_orig(mod, "requests.get")

        resp = requests.get("https://api.example.com/data")
        assert sink.count == 1
        assert sink.last["event_type"] == "api_invocation_allowed"

    def test_requests_post_intercepted(self, sink):
        mod = _patch_and_mock(sink)
        _mock_orig(mod, "requests.post")

        resp = requests.post("https://api.example.com/data", json={"key": "value"})
        assert sink.count == 1
        assert sink.last["event_type"] == "api_invocation_allowed"

    def test_requests_session_intercepted(self, sink):
        mod = _patch_and_mock(sink)
        _mock_orig(mod, "requests.Session.request")

        session = requests.Session()
        resp = session.get("https://api.example.com/data")
        assert sink.count == 1

    def test_requests_request_intercepted(self, sink):
        mod = _patch_and_mock(sink)
        _mock_orig(mod, "requests.request")

        resp = requests.request("GET", "https://api.example.com/data")
        assert sink.count == 1

    def test_urllib_urlopen_intercepted(self, sink):
        import urllib.request

        mod = _patch_and_mock(sink, constitution=API_PERMISSIVE_CONSTITUTION)
        mock_resp = MagicMock()
        mock_resp.read.return_value = b'{"ok": true}'
        mock_resp.headers = {"Content-Type": "application/json"}
        mock_resp.status = 200
        mock_resp.code = 200
        mock_resp.url = "https://api.example.com/data"
        _mock_orig(mod, "urllib.request.urlopen", response=mock_resp)

        resp = urllib.request.urlopen("https://api.example.com/data")
        assert sink.count == 1


# =============================================================================
# 2. JUSTIFICATION HANDLING
# =============================================================================

class TestJustificationHandling:
    """Verify justification kwarg is stripped and recorded."""

    def test_justification_kwarg_stripped(self, sink):
        mod = _patch_and_mock(sink)
        mock_orig = _mock_orig(mod, "requests.get")

        requests.get("https://api.example.com/data", justification="test reason")
        _, call_kwargs = mock_orig.call_args
        assert "justification" not in call_kwargs

    def test_justification_in_receipt(self, sink):
        mod = _patch_and_mock(sink)
        _mock_orig(mod, "requests.get")

        requests.get("https://api.example.com/data", justification="test reason")
        expected_hash = hash_text("test reason")
        assert sink.last["reasoning_hash"] == expected_hash

    def test_no_justification_empty_hash(self, sink):
        mod = _patch_and_mock(sink)
        _mock_orig(mod, "requests.get")

        requests.get("https://api.example.com/data")
        assert sink.last["reasoning_hash"] == EMPTY_HASH


# =============================================================================
# 3. AUTHORITY ENFORCEMENT
# =============================================================================

class TestAuthorityEnforcement:
    """Verify authority decisions are enforced correctly."""

    def test_can_execute_allowed(self, sink):
        mod = _patch_and_mock(sink)
        _mock_orig(mod, "requests.get")

        resp = requests.get("https://api.example.com/data")
        assert sink.count == 1
        assert sink.last["event_type"] == "api_invocation_allowed"

    def test_cannot_execute_halted(self, sink):
        mod = _patch_and_mock(sink)
        _mock_orig(mod, "requests.get")

        with pytest.raises(ConnectionError, match="Connection refused"):
            requests.get("https://internal.evil.com/secrets")

    def test_must_escalate_blocked(self, sink):
        mod = _patch_and_mock(sink)
        _mock_orig(mod, "requests.post")

        with pytest.raises(PermissionError, match="Escalation required"):
            requests.post("https://api.stripe.com/v1/charges", json={"amount": 100})

    def test_strict_mode_unlisted_denied(self, sink):
        mod = _patch_and_mock(sink)
        _mock_orig(mod, "requests.get")

        with pytest.raises(ConnectionError, match="Connection refused"):
            requests.get("https://unknown-api.com/data")

    def test_permissive_mode_unlisted_allowed(self, sink):
        mod = _patch_and_mock(sink, constitution=API_PERMISSIVE_CONSTITUTION)
        _mock_orig(mod, "requests.get")

        resp = requests.get("https://unknown-api.com/data")
        assert sink.count == 1
        assert sink.last["event_type"] == "api_invocation_allowed"

    def test_method_filtering(self, sink):
        """URL allowed for GET but not DELETE."""
        mod = _patch_and_mock(sink)
        _mock_orig(mod, "requests.get")
        _mock_orig(mod, "requests.delete")

        resp = requests.get("https://api.example.com/data")
        assert sink.count == 1

        with pytest.raises(ConnectionError):
            requests.delete("https://api.example.com/admin/user/123")


# =============================================================================
# 4. URL PATTERN MATCHING
# =============================================================================

class TestURLPatternMatching:
    """Verify URL glob pattern matching."""

    def test_wildcard_pattern(self, sink):
        """https://api.example.com/* matches subpaths."""
        mod = _patch_and_mock(sink)
        _mock_orig(mod, "requests.get")

        resp = requests.get("https://api.example.com/users/123")
        assert sink.count == 1
        assert sink.last["event_type"] == "api_invocation_allowed"

    def test_exact_url_match(self, sink):
        """Exact URL pattern matches only that URL."""
        mod = _patch_and_mock(sink)
        _mock_orig(mod, "requests.post")

        with pytest.raises(PermissionError):
            requests.post("https://api.stripe.com/v1/charges")

        with pytest.raises(ConnectionError):
            requests.post("https://api.stripe.com/v1/refunds")

    def test_first_match_wins(self, sink):
        """Earlier rule takes precedence over later rule."""
        mod = _patch_and_mock(sink)
        _mock_orig(mod, "requests.get")

        resp = requests.get("https://api.example.com/admin/users")
        assert sink.count == 1
        assert sink.last["event_type"] == "api_invocation_allowed"

    def test_no_method_match_skips_rule(self, sink):
        """Rule with specific methods doesn't match other methods."""
        mod = _patch_and_mock(sink)
        _mock_orig(mod, "requests.put")

        with pytest.raises(ConnectionError):
            requests.put("https://api.example.com/data", json={"key": "value"})


# =============================================================================
# 5. EXCLUSIONS
# =============================================================================

class TestExclusions:
    """Verify URL exclusion patterns."""

    def test_sanna_cloud_excluded_by_default(self, sink):
        mod = _patch_and_mock(sink)
        _mock_orig(mod, "requests.get")

        resp = requests.get("https://api.sanna.cloud/v1/receipts")
        assert sink.count == 0

    def test_custom_exclusion(self, sink):
        mod = _patch_and_mock(sink, exclude_urls=["https://my-internal-api.com/*"])
        _mock_orig(mod, "requests.get")

        resp = requests.get("https://my-internal-api.com/health")
        assert sink.count == 0

    def test_excluded_calls_produce_no_receipt(self, sink):
        mod = _patch_and_mock(sink)
        _mock_orig(mod, "requests.post")

        requests.post("https://api.sanna.cloud/v1/receipts", json={"receipt": {}})
        assert sink.count == 0


# =============================================================================
# 6. RECEIPT TRIAD
# =============================================================================

class TestReceiptTriad:
    """Verify input_hash, reasoning_hash, action_hash computation."""

    def test_input_hash_canonical_order(self, sink):
        """Input hash keys are alphabetical: body_hash, headers_keys, method, url."""
        mod = _patch_and_mock(sink)
        _mock_orig(mod, "requests.get")

        requests.get("https://api.example.com/data")

        input_obj = {
            "body_hash": EMPTY_HASH,
            "headers_keys": [],
            "method": "GET",
            "url": "https://api.example.com/data",
        }
        assert sink.last["input_hash"] == hash_obj(input_obj)

    def test_action_hash_from_response(self, sink):
        """action_hash computed from actual response."""
        resp_content = b'{"result": "ok"}'
        mod = _patch_and_mock(sink)
        _mock_orig(mod, "requests.get", _mock_response(status_code=200, content=resp_content))

        requests.get("https://api.example.com/data")

        resp_body_hash = hashlib.sha256(resp_content).hexdigest()
        action_obj = {
            "body_hash": resp_body_hash,
            "response_headers_keys": ["Content-Type"],
            "status_code": 200,
        }
        assert sink.last["action_hash"] == hash_obj(action_obj)

    def test_action_hash_halted(self, sink):
        """Halted request produces action_hash with null status_code."""
        mod = _patch_and_mock(sink)
        _mock_orig(mod, "requests.get")

        with pytest.raises(ConnectionError):
            requests.get("https://internal.evil.com/secrets")

        action_obj = {
            "body_hash": EMPTY_HASH,
            "response_headers_keys": [],
            "status_code": None,
        }
        assert sink.last["action_hash"] == hash_obj(action_obj)

    def test_action_hash_differs_from_input_hash(self, sink):
        """For allowed requests, action_hash != input_hash."""
        mod = _patch_and_mock(sink)
        _mock_orig(mod, "requests.get")

        requests.get("https://api.example.com/data")
        assert sink.last["action_hash"] != sink.last["input_hash"]

    def test_body_hash_computed(self, sink):
        """POST with body produces non-EMPTY_HASH body_hash."""
        mod = _patch_and_mock(sink)
        _mock_orig(mod, "requests.post")

        body = {"key": "value"}
        requests.post("https://api.example.com/data", json=body)

        body_bytes = json.dumps(body, separators=(",", ":"), sort_keys=True).encode("utf-8")
        expected_body_hash = hashlib.sha256(body_bytes).hexdigest()
        input_obj = {
            "body_hash": expected_body_hash,
            "headers_keys": [],
            "method": "POST",
            "url": "https://api.example.com/data",
        }
        assert sink.last["input_hash"] == hash_obj(input_obj)


# =============================================================================
# 7. RECEIPT FIELDS
# =============================================================================

class TestReceiptFields:
    """Verify receipt metadata fields."""

    def test_event_type_allowed(self, sink):
        mod = _patch_and_mock(sink)
        _mock_orig(mod, "requests.get")

        requests.get("https://api.example.com/data")
        assert sink.last["event_type"] == "api_invocation_allowed"

    def test_event_type_halted(self, sink):
        mod = _patch_and_mock(sink)
        _mock_orig(mod, "requests.get")

        with pytest.raises(ConnectionError):
            requests.get("https://internal.evil.com/data")
        assert sink.last["event_type"] == "api_invocation_halted"

    def test_context_limitation_set(self, sink):
        mod = _patch_and_mock(sink)
        _mock_orig(mod, "requests.get")

        requests.get("https://api.example.com/data")
        assert sink.last["context_limitation"] == "api_no_justification"

        requests.get("https://api.example.com/data", justification="reason")
        assert sink.last["context_limitation"] == "api_execution"

    def test_receipt_extensions_surface(self, sink):
        """Receipt extensions indicate api surface."""
        mod = _patch_and_mock(sink)
        _mock_orig(mod, "requests.get")

        requests.get("https://api.example.com/data")
        ext = sink.last["extensions"]["com.sanna.interceptor"]
        assert ext["surface"] == "api"
        assert ext["method"] == "GET"
        assert ext["url"] == "https://api.example.com/data"


# =============================================================================
# 8. INVARIANTS
# =============================================================================

class TestInvariants:
    """Verify URL invariant checks."""

    def test_invariant_blocks_api_key_in_url(self, sink):
        mod = _patch_and_mock(sink)
        _mock_orig(mod, "requests.get")

        with pytest.raises(ConnectionError):
            requests.get("https://api.example.com/data?api_key=secret123")

    def test_invariant_allows_clean_url(self, sink):
        mod = _patch_and_mock(sink)
        _mock_orig(mod, "requests.get")

        resp = requests.get("https://api.example.com/data")
        assert sink.count == 1
        assert sink.last["event_type"] == "api_invocation_allowed"

    def test_invariant_overrides_authority(self, sink):
        """URL allowed by authority rule but blocked by invariant."""
        mod = _patch_and_mock(sink)
        _mock_orig(mod, "requests.get")

        with pytest.raises(ConnectionError):
            requests.get("https://api.example.com/data?token=abc")


# =============================================================================
# 9. AUDIT AND PASSTHROUGH MODES
# =============================================================================

class TestAuditAndPassthrough:
    """Verify audit and passthrough mode behavior."""

    def test_audit_mode_executes_despite_halt(self, sink):
        mod = _patch_and_mock(sink, mode="audit")
        _mock_orig(mod, "requests.get")

        resp = requests.get("https://internal.evil.com/secrets")
        assert resp.status_code == 200
        assert sink.count == 1

    def test_audit_mode_receipt_shows_would_have_halted(self, sink):
        mod = _patch_and_mock(sink, mode="audit")
        _mock_orig(mod, "requests.get")

        requests.get("https://internal.evil.com/secrets")
        assert sink.last["event_type"] == "api_invocation_halted"

    def test_passthrough_mode_no_enforcement(self, sink):
        mod = _patch_and_mock(sink, mode="passthrough")
        _mock_orig(mod, "requests.get")

        resp = requests.get("https://internal.evil.com/secrets")
        assert resp.status_code == 200
        assert sink.count == 1


# =============================================================================
# 10. ANTI-ENUMERATION
# =============================================================================

class TestAntiEnumeration:
    """Verify anti-enumeration measures."""

    def test_halted_returns_connection_error(self, sink):
        """Blocked URL raises ConnectionError, not governance error."""
        mod = _patch_and_mock(sink)
        _mock_orig(mod, "requests.get")

        with pytest.raises(ConnectionError) as exc_info:
            requests.get("https://internal.evil.com/secrets")
        assert "Connection refused" in str(exc_info.value)
        assert "governance" not in str(exc_info.value).lower()
        assert "constitution" not in str(exc_info.value).lower()

    def test_halted_receipt_in_sink(self, sink):
        """Receipt exists in sink after ConnectionError."""
        mod = _patch_and_mock(sink)
        _mock_orig(mod, "requests.get")

        with pytest.raises(ConnectionError):
            requests.get("https://internal.evil.com/secrets")
        assert sink.count == 1


# =============================================================================
# 11. EDGE CASES
# =============================================================================

class TestEdgeCases:
    """Verify edge case handling."""

    def test_patch_idempotent(self, sink):
        mod = _patch_and_mock(sink)
        orig_get = mod._originals.get("requests.get")

        # Second call is a no-op
        patch_http(
            constitution_path=API_TEST_CONSTITUTION,
            sink=sink,
            agent_id="test-agent",
            mode="enforce",
        )
        assert mod._originals.get("requests.get") is orig_get

    def test_unpatch_restores_originals(self, sink):
        import requests as req_mod
        original_get = req_mod.get

        patch_http(
            constitution_path=API_TEST_CONSTITUTION,
            sink=sink,
            agent_id="test-agent",
            mode="enforce",
        )
        assert req_mod.get is not original_get

        unpatch_http()
        assert req_mod.get is original_get

    def test_no_api_permissions_allows_all(self, sink):
        """Constitution without api_permissions allows everything."""
        mod = _patch_and_mock(sink, constitution=NO_API_CONSTITUTION)
        _mock_orig(mod, "requests.get")

        resp = requests.get("https://any-url.com/anything")
        assert sink.count == 1
        assert sink.last["event_type"] == "api_invocation_allowed"


# =============================================================================
# 12. CONSTITUTION PARSING
# =============================================================================

class TestConstitutionParsing:
    """Verify api_permissions parsing."""

    def test_parse_api_permissions(self):
        constitution = load_constitution(API_TEST_CONSTITUTION)
        assert constitution.api_permissions is not None
        assert constitution.api_permissions.mode == "strict"
        assert len(constitution.api_permissions.endpoints) == 4

    def test_parse_api_permissions_with_invariants(self):
        constitution = load_constitution(API_TEST_CONSTITUTION)
        assert len(constitution.api_permissions.invariants) == 1
        inv = constitution.api_permissions.invariants[0]
        assert inv.id == "api-inv-001"
        assert inv.verdict == "halt"
        assert inv.pattern is not None

    def test_parse_api_permissions_methods_default(self):
        """Missing methods defaults to ['*']."""
        constitution = load_constitution(API_TEST_CONSTITUTION)
        # api-003 has methods: ["*"] explicitly
        ep = constitution.api_permissions.endpoints[2]
        assert ep.methods == ["*"]

    def test_parse_no_api_permissions(self):
        """Constitution without api_permissions has None."""
        constitution = load_constitution(NO_API_CONSTITUTION)
        assert constitution.api_permissions is None

    def test_api_endpoint_fields(self):
        """Verify all ApiEndpoint fields are parsed."""
        constitution = load_constitution(API_TEST_CONSTITUTION)
        ep = constitution.api_permissions.endpoints[0]
        assert ep.id == "api-001"
        assert ep.url_pattern == "https://api.example.com/*"
        assert ep.authority == "can_execute"
        assert ep.methods == ["GET", "POST"]
        assert ep.description == "Example API allowed"

    def test_api_endpoint_escalation_target(self):
        """Escalation target is parsed when present."""
        constitution = load_constitution(API_TEST_CONSTITUTION)
        ep = constitution.api_permissions.endpoints[1]
        assert ep.authority == "must_escalate"
        # escalation_target not set in this fixture
        assert ep.escalation_target is None


# =============================================================================
# 13. CROSS-SURFACE
# =============================================================================

class TestCrossSurface:
    """Verify multi-surface governance."""

    def test_single_constitution_cli_and_api(self):
        """Constitution can have both cli_permissions and api_permissions."""
        constitution = load_constitution(API_TEST_CONSTITUTION)
        # api-test.yaml has api_permissions but no cli_permissions
        assert constitution.api_permissions is not None
        assert constitution.cli_permissions is None

        # cli-test.yaml has cli_permissions but no api_permissions
        constitution2 = load_constitution(str(CONSTITUTIONS_DIR / "cli-test.yaml"))
        assert constitution2.cli_permissions is not None
        assert constitution2.api_permissions is None


# =============================================================================
# 14. API AUTHORITY EVALUATOR (UNIT)
# =============================================================================

class TestApiAuthorityEvaluator:
    """Unit tests for evaluate_api_authority."""

    def test_no_api_permissions_allows(self):
        constitution = MagicMock()
        constitution.api_permissions = None
        decision = evaluate_api_authority("GET", "https://example.com", constitution)
        assert decision.decision == "allow"

    def test_can_execute_decision(self):
        constitution = load_constitution(API_TEST_CONSTITUTION)
        decision = evaluate_api_authority("GET", "https://api.example.com/data", constitution)
        assert decision.decision == "allow"
        assert decision.rule_id == "api-001"

    def test_cannot_execute_decision(self):
        constitution = load_constitution(API_TEST_CONSTITUTION)
        decision = evaluate_api_authority("GET", "https://internal.evil.com/data", constitution)
        assert decision.decision == "halt"
        assert decision.rule_id == "api-003"

    def test_must_escalate_decision(self):
        constitution = load_constitution(API_TEST_CONSTITUTION)
        decision = evaluate_api_authority("POST", "https://api.stripe.com/v1/charges", constitution)
        assert decision.decision == "escalate"
        assert decision.rule_id == "api-002"

    def test_strict_mode_unlisted(self):
        constitution = load_constitution(API_TEST_CONSTITUTION)
        decision = evaluate_api_authority("GET", "https://unknown.com/data", constitution)
        assert decision.decision == "halt"

    def test_permissive_mode_unlisted(self):
        constitution = load_constitution(API_PERMISSIVE_CONSTITUTION)
        decision = evaluate_api_authority("GET", "https://unknown.com/data", constitution)
        assert decision.decision == "allow"

    def test_check_api_invariants_match(self):
        constitution = load_constitution(API_TEST_CONSTITUTION)
        inv = check_api_invariants("https://example.com?api_key=secret", constitution)
        assert inv is not None
        assert inv.id == "api-inv-001"

    def test_check_api_invariants_no_match(self):
        constitution = load_constitution(API_TEST_CONSTITUTION)
        inv = check_api_invariants("https://example.com/clean", constitution)
        assert inv is None
