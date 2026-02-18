"""Tests for v0.13.2 webhook hardening (Prompt 2).

FIX-8:  Webhook redirect blocking — all redirect codes (301, 302, 307, 308)
        are blocked by _NoRedirectHandler raising HTTPError.
FIX-13: Webhook response body size limit — bounded read prevents memory
        exhaustion from malicious webhook endpoints.
"""

from __future__ import annotations

import io
import json
import logging
import time
import threading
import urllib.error
import urllib.request
from http.server import HTTPServer, BaseHTTPRequestHandler
from unittest.mock import patch, MagicMock

import pytest

try:
    import mcp  # noqa: F401
    _has_mcp = True
except (ImportError, ModuleNotFoundError):
    _has_mcp = False

requires_mcp = pytest.mark.skipif(not _has_mcp, reason="mcp extra not installed")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

class _RedirectHandler(BaseHTTPRequestHandler):
    """HTTP handler that returns a redirect with a configurable status code.

    The redirect target and status code are set via class attributes so the
    test can configure them before starting the server.
    """
    redirect_code: int = 302
    redirect_target: str = "https://evil.example.com/steal"

    def do_POST(self, *_args):
        self.send_response(self.redirect_code)
        self.send_header("Location", self.redirect_target)
        self.end_headers()

    def log_message(self, *_args):
        pass  # Suppress server log output during tests


class _LargeResponseHandler(BaseHTTPRequestHandler):
    """HTTP handler that streams a response larger than the size limit."""
    response_size: int = 2 * 1024 * 1024  # 2 MB (over the 1 MB limit)

    def do_POST(self, *_args):
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        # Announce a large content length
        self.send_header("Content-Length", str(self.response_size))
        self.end_headers()
        # Write in chunks to avoid allocating a huge buffer
        chunk = b"X" * min(65536, self.response_size)
        written = 0
        try:
            while written < self.response_size:
                to_write = min(len(chunk), self.response_size - written)
                self.wfile.write(chunk[:to_write])
                written += to_write
        except (BrokenPipeError, ConnectionResetError):
            pass  # Client disconnected — expected when size limit is hit

    def log_message(self, *_args):
        pass


@pytest.fixture()
def redirect_server():
    """Start a local HTTP server that returns redirects."""
    server = HTTPServer(("127.0.0.1", 0), _RedirectHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server, port
    server.shutdown()


@pytest.fixture()
def large_response_server():
    """Start a local HTTP server that returns oversized responses."""
    server = HTTPServer(("127.0.0.1", 0), _LargeResponseHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server, port
    server.shutdown()


def _make_gateway_stub(webhook_url: str):
    """Create a minimal SannaGateway stub for testing _deliver_token_via_webhook."""
    pytest.importorskip("mcp")
    from sanna.gateway.server import SannaGateway
    gw = object.__new__(SannaGateway)
    gw._approval_webhook_url = webhook_url
    return gw


def _make_entry(escalation_id: str = "esc_test"):
    """Create a minimal PendingEscalation for testing."""
    from sanna.gateway.server import PendingEscalation
    return PendingEscalation(
        escalation_id=escalation_id,
        prefixed_name="mock_update",
        original_name="update",
        arguments={},
        server_name="mock",
        reason="test redirect",
        created_at="2024-01-01T00:00:00Z",
    )


def _make_token_info():
    return {"token": "test-token-abc", "expires_at": time.time() + 300}


# ---------------------------------------------------------------------------
# FIX-8: Redirect blocking
# ---------------------------------------------------------------------------


@requires_mcp
class TestWebhookRedirectBlocking:
    """FIX-8: _NoRedirectHandler blocks ALL redirect status codes."""

    def _run_redirect_test(self, redirect_server, status_code, caplog):
        """Common helper: configure redirect code, call webhook, assert blocked."""
        server, port = redirect_server
        # Reconfigure handler for this specific status code
        _RedirectHandler.redirect_code = status_code
        _RedirectHandler.redirect_target = "https://evil.example.com/steal"

        webhook_url = f"http://127.0.0.1:{port}/hook"
        gw = _make_gateway_stub(webhook_url)
        entry = _make_entry(f"esc_redirect_{status_code}")
        token_info = _make_token_info()

        # Bypass the SSRF validation (we're using localhost deliberately)
        with patch("sanna.gateway.config.validate_webhook_url"), \
             caplog.at_level(logging.WARNING, logger="sanna.gateway.server"):
            gw._deliver_token_via_webhook(entry, token_info)

        # Verify a redirect warning was logged
        redirect_msgs = [
            r for r in caplog.records
            if "redirect" in r.message.lower() and "blocked" in r.message.lower()
        ]
        assert len(redirect_msgs) >= 1, (
            f"Expected a redirect-blocked warning for {status_code}, "
            f"got: {[r.message for r in caplog.records]}"
        )

    def test_301_blocked(self, redirect_server, caplog):
        """301 Moved Permanently redirect is blocked by _NoRedirectHandler."""
        self._run_redirect_test(redirect_server, 301, caplog)

    def test_302_blocked(self, redirect_server, caplog):
        """302 Found redirect is blocked by _NoRedirectHandler."""
        self._run_redirect_test(redirect_server, 302, caplog)

    def test_307_blocked(self, redirect_server, caplog):
        """307 Temporary Redirect is blocked by _NoRedirectHandler."""
        self._run_redirect_test(redirect_server, 307, caplog)

    def test_308_blocked(self, redirect_server, caplog):
        """308 Permanent Redirect is blocked by _NoRedirectHandler."""
        self._run_redirect_test(redirect_server, 308, caplog)


# ---------------------------------------------------------------------------
# FIX-13: Response body size limit
# ---------------------------------------------------------------------------


@requires_mcp
class TestWebhookResponseSizeLimit:
    """FIX-13: Webhook response body read is bounded to 1 MB."""

    def test_response_size_limited(self, large_response_server, caplog):
        """Webhook response body read is bounded.

        The server sends a 2 MB response but the client should only read
        up to 1 MB (the _MAX_WEBHOOK_RESPONSE_BYTES limit).  We verify
        this by checking that the method completes without error and does
        not consume the full 2 MB into memory.
        """
        server, port = large_response_server
        webhook_url = f"http://127.0.0.1:{port}/hook"
        gw = _make_gateway_stub(webhook_url)
        entry = _make_entry("esc_size_limit")
        token_info = _make_token_info()

        # Track how much data resp.read() actually returns
        read_sizes: list[int] = []
        _original_open = urllib.request.OpenerDirector.open

        def _tracking_open(self_opener, req, *args, **kwargs):
            resp = _original_open(self_opener, req, *args, **kwargs)
            original_read = resp.read

            def bounded_read(size=-1):
                data = original_read(size)
                read_sizes.append(len(data))
                return data

            resp.read = bounded_read
            return resp

        with patch("sanna.gateway.config.validate_webhook_url"), \
             patch.object(urllib.request.OpenerDirector, "open", _tracking_open):
            gw._deliver_token_via_webhook(entry, token_info)

        # The read should have been bounded — at most 1 MB
        assert len(read_sizes) >= 1, "resp.read() was never called"
        total_read = sum(read_sizes)
        assert total_read <= 1024 * 1024, (
            f"Read {total_read} bytes, expected at most 1 MB (1048576)"
        )
