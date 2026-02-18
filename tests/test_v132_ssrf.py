"""Tests for v0.13.2 SSRF hardening (Prompt 1).

FIX-1: DNS rebinding re-validation at send time
FIX-37: NAT64 and CGNAT IP ranges blocked
FIX-43: DNS resolution timeout
FIX-15: IPv6 loopback insecure webhook
FIX-16: IPv4-mapped IPv6
"""

import os
import ipaddress
from unittest import mock

import pytest

from sanna.gateway.config import _is_blocked_ip, validate_webhook_url, GatewayConfigError


class TestBlockedIPRanges:
    def test_cgnat_blocked(self):
        addr = ipaddress.ip_address("100.64.0.1")
        reason = _is_blocked_ip(addr)
        assert reason is not None
        assert "CGNAT" in reason or "shared" in reason.lower()

    def test_nat64_blocked(self):
        addr = ipaddress.ip_address("64:ff9b::a9fe:a9fe")
        reason = _is_blocked_ip(addr)
        assert reason is not None
        assert "NAT64" in reason

    def test_ipv4_mapped_loopback_blocked(self):
        addr = ipaddress.ip_address("::ffff:127.0.0.1")
        reason = _is_blocked_ip(addr)
        assert reason is not None

    def test_ipv4_mapped_metadata_blocked(self):
        addr = ipaddress.ip_address("::ffff:169.254.169.254")
        reason = _is_blocked_ip(addr)
        assert reason is not None

    def test_public_ip_not_blocked(self):
        addr = ipaddress.ip_address("8.8.8.8")
        assert _is_blocked_ip(addr) is None


class TestIPv6LoopbackInsecure:
    def test_ipv6_loopback_accepted_with_env_var(self):
        with mock.patch.dict(os.environ, {"SANNA_ALLOW_INSECURE_WEBHOOK": "1"}):
            # Should NOT raise (IPv6 loopback is local)
            validate_webhook_url("http://[::1]:8080/hook")

    def test_ipv6_loopback_rejected_without_env(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            os.environ.pop("SANNA_ALLOW_INSECURE_WEBHOOK", None)
            with pytest.raises(GatewayConfigError):
                validate_webhook_url("http://[::1]:8080/hook")


class TestDNSTimeout:
    def test_dns_timeout_raises(self):
        """DNS resolution that hangs should timeout after ~5 seconds."""
        import socket
        # Use a hostname that will definitely fail or hang
        with mock.patch("socket.getaddrinfo", side_effect=lambda *a, **k: __import__("time").sleep(10)):
            with pytest.raises(GatewayConfigError, match="timed out"):
                validate_webhook_url("https://slow-dns-example.invalid/hook")
