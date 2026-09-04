"""
PhishNetra - SSRF & DNS Rebinding Protection Unit Tests
Module: services.ml.tests.test_ssrf
Milestone: 3
"""

import pytest
from app.security.ssrf import ssrf_validator


class TestSSRFValidator:
    """
    Test suite verifying strict SSRF and DNS Rebinding protections.
    """

    @pytest.mark.parametrize("blocked_url", [
        "http://localhost",
        "http://localhost:8080/admin",
        "http://127.0.0.1",
        "http://127.0.0.1:3000/api",
        "http://0.0.0.0",
        "http://10.0.0.1/status",
        "http://192.168.1.1/router",
        "http://172.16.0.1/login",
        "http://169.254.169.254/latest/meta-data/",
        "http://100.100.100.200/latest/meta-data/",
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://instance-data/latest/meta-data/",
        "http://[::1]/",
        "http://[::ffff:127.0.0.1]/",
        "http://2130706433/",       # Decimal IP for 127.0.0.1
        "http://0x7f000001/",       # Hex IP for 127.0.0.1
        "http://0177.0.0.1/",       # Octal IP for 127.0.0.1
        "ftp://example.com/file",   # Prohibited scheme
        "file:///etc/passwd",       # File scheme
        "gopher://127.0.0.1:70/"   # Gopher scheme
    ])
    def test_blocks_prohibited_targets(self, blocked_url: str):
        is_safe, reason, host = ssrf_validator.validate_url(blocked_url)
        assert is_safe is False
        assert reason is not None
        assert len(reason) > 0

    @pytest.mark.parametrize("safe_url", [
        "https://example.com",
        "https://www.google.com/search?q=cybersecurity",
        "https://github.com/login",
        "https://microsoft.com/en-us"
    ])
    def test_allows_legitimate_public_urls(self, safe_url: str):
        is_safe, reason, host = ssrf_validator.validate_url(safe_url)
        assert is_safe is True
        assert reason is None
        assert host is not None

    def test_dns_rebinding_defense_for_local_domain(self):
        # localhost resolves to 127.0.0.1 / ::1
        is_safe, reason, ips = ssrf_validator.resolve_and_validate("localhost")
        assert is_safe is False
        assert "prohibited" in reason.lower() or "local" in reason.lower()

    def test_alternative_ip_decoding(self):
        dec_ip = ssrf_validator.parse_alternative_ip("2130706433")
        assert str(dec_ip) == "127.0.0.1"

        hex_ip = ssrf_validator.parse_alternative_ip("0x7f000001")
        assert str(dec_ip) == "127.0.0.1"

        oct_ip = ssrf_validator.parse_alternative_ip("0177.0.0.1")
        assert str(oct_ip) == "127.0.0.1"
