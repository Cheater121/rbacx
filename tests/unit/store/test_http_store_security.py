"""Tests for HTTPPolicySource security hardening (v1.9.4).

Covers:
- URL scheme whitelist (``allowed_schemes``)
- SSRF guard via IP-literal blocking (``block_private_ips``)
- ``_is_private_ip`` helper
- ``verify_ssl``, ``timeout``, ``allow_redirects`` are forwarded to requests.get
- Backward-compatible defaults (http + https allowed, no SSRF guard, SSL on)
"""

import sys
import types

import pytest

from rbacx.store.http_store import HTTPPolicySource, _is_private_ip

# ---------------------------------------------------------------------------
# _is_private_ip helper
# ---------------------------------------------------------------------------


class TestIsPrivateIp:
    """Unit tests for the SSRF guard IP classifier."""

    @pytest.mark.parametrize(
        "host",
        [
            "127.0.0.1",
            "127.0.0.2",
            "127.255.255.255",  # loopback
            "10.0.0.1",
            "10.255.255.255",  # RFC-1918
            "172.16.0.1",
            "172.31.255.255",  # RFC-1918
            "192.168.0.1",
            "192.168.255.255",  # RFC-1918
            "169.254.0.1",
            "169.254.169.254",  # link-local (AWS metadata)
            "0.0.0.1",  # "this" network
            "::1",  # IPv6 loopback
            "fc00::1",
            "fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",  # IPv6 ULA
            "fe80::1",
            "fe80::dead:beef",  # IPv6 link-local
        ],
    )
    def test_private_addresses_return_true(self, host: str) -> None:
        assert _is_private_ip(host) is True

    @pytest.mark.parametrize(
        "host",
        [
            "8.8.8.8",
            "1.1.1.1",
            "93.184.216.34",  # public IPv4
            "2001:4860:4860::8888",  # Google public DNS IPv6
            "example.com",
            "localhost",
            "my-server",  # hostnames — not resolved
            "",  # empty string
        ],
    )
    def test_public_and_hostname_addresses_return_false(self, host: str) -> None:
        assert _is_private_ip(host) is False


# ---------------------------------------------------------------------------
# Constructor: scheme validation
# ---------------------------------------------------------------------------


class TestSchemeValidation:
    """HTTPPolicySource rejects URLs with disallowed schemes at construction time."""

    def test_http_allowed_by_default(self) -> None:
        src = HTTPPolicySource("http://example.com/p.json")
        assert src.url == "http://example.com/p.json"

    def test_https_allowed_by_default(self) -> None:
        src = HTTPPolicySource("https://example.com/p.json")
        assert src.url == "https://example.com/p.json"

    def test_ftp_rejected_by_default(self) -> None:
        with pytest.raises(ValueError, match="ftp"):
            HTTPPolicySource("ftp://example.com/p.json")

    def test_file_scheme_rejected_by_default(self) -> None:
        with pytest.raises(ValueError, match="file"):
            HTTPPolicySource("file:///etc/passwd")

    def test_https_only_mode_rejects_http(self) -> None:
        with pytest.raises(ValueError, match="http"):
            HTTPPolicySource("http://example.com/p.json", allowed_schemes=("https",))

    def test_https_only_mode_accepts_https(self) -> None:
        src = HTTPPolicySource("https://example.com/p.json", allowed_schemes=("https",))
        assert src.url == "https://example.com/p.json"

    def test_custom_scheme_whitelist(self) -> None:
        with pytest.raises(ValueError):
            HTTPPolicySource("https://example.com/p.json", allowed_schemes=("http",))

    def test_error_message_includes_allowed_schemes(self) -> None:
        with pytest.raises(ValueError, match="allowed"):
            HTTPPolicySource("ftp://example.com/p.json", allowed_schemes=("http", "https"))


# ---------------------------------------------------------------------------
# Constructor: SSRF guard (block_private_ips)
# ---------------------------------------------------------------------------


class TestSsrfGuard:
    """block_private_ips=True blocks numeric private IP literals at construction."""

    @pytest.mark.parametrize(
        "url",
        [
            "http://127.0.0.1/p.json",
            "http://10.0.0.1/p.json",
            "http://192.168.1.1/p.json",
            "http://172.16.5.5/p.json",
            "http://169.254.169.254/p.json",  # AWS EC2 metadata endpoint
            "http://[::1]/p.json",  # IPv6 loopback
        ],
    )
    def test_private_ip_blocked_when_guard_enabled(self, url: str) -> None:
        with pytest.raises(ValueError, match="SSRF"):
            HTTPPolicySource(url, block_private_ips=True)

    def test_public_ip_allowed_when_guard_enabled(self) -> None:
        src = HTTPPolicySource("http://8.8.8.8/p.json", block_private_ips=True)
        assert src.url == "http://8.8.8.8/p.json"

    def test_hostname_allowed_when_guard_enabled(self) -> None:
        """Hostnames are not resolved — DNS-based SSRF is out of scope."""
        src = HTTPPolicySource("http://localhost/p.json", block_private_ips=True)
        assert src.url == "http://localhost/p.json"

    def test_private_ip_allowed_when_guard_disabled(self) -> None:
        """Default behaviour: no SSRF guard — private IPs are permitted."""
        src = HTTPPolicySource("http://127.0.0.1/p.json")
        assert src.url == "http://127.0.0.1/p.json"

    def test_error_message_includes_host(self) -> None:
        with pytest.raises(ValueError, match="127.0.0.1"):
            HTTPPolicySource("http://127.0.0.1/p.json", block_private_ips=True)


# ---------------------------------------------------------------------------
# Constructor: security parameter storage
# ---------------------------------------------------------------------------


class TestSecurityParamStorage:
    """Security parameters are stored and have correct defaults."""

    def test_verify_ssl_default_true(self) -> None:
        src = HTTPPolicySource("http://example.com/p.json")
        assert src.verify_ssl is True

    def test_verify_ssl_can_be_disabled(self) -> None:
        src = HTTPPolicySource("http://example.com/p.json", verify_ssl=False)
        assert src.verify_ssl is False

    def test_timeout_default(self) -> None:
        src = HTTPPolicySource("http://example.com/p.json")
        assert src.timeout == 5.0

    def test_timeout_custom(self) -> None:
        src = HTTPPolicySource("http://example.com/p.json", timeout=30.0)
        assert src.timeout == 30.0

    def test_allow_redirects_default_true(self) -> None:
        src = HTTPPolicySource("http://example.com/p.json")
        assert src.allow_redirects is True

    def test_allow_redirects_can_be_disabled(self) -> None:
        src = HTTPPolicySource("http://example.com/p.json", allow_redirects=False)
        assert src.allow_redirects is False


# ---------------------------------------------------------------------------
# load(): security params are forwarded to requests.get
# ---------------------------------------------------------------------------


class TestSecurityParamsForwardedToRequests:
    """verify, timeout, allow_redirects must be passed as kwargs to requests.get."""

    def _install_capture(self, monkeypatch) -> dict:
        """Install a fake requests module that captures kwargs passed to get()."""
        captured: dict = {}

        class Resp:
            status_code = 200
            headers = {"ETag": "E1"}

            def json(self):
                return {"rules": []}

            def raise_for_status(self):
                pass

        def fake_get(url, **kwargs):
            captured.update(kwargs)
            return Resp()

        monkeypatch.setitem(sys.modules, "requests", types.SimpleNamespace(get=fake_get))
        return captured

    def test_verify_ssl_true_forwarded(self, monkeypatch) -> None:
        captured = self._install_capture(monkeypatch)
        src = HTTPPolicySource("http://example.com/p.json", verify_ssl=True)
        src.load()
        assert captured.get("verify") is True

    def test_verify_ssl_false_forwarded(self, monkeypatch) -> None:
        captured = self._install_capture(monkeypatch)
        src = HTTPPolicySource("http://example.com/p.json", verify_ssl=False)
        src.load()
        assert captured.get("verify") is False

    def test_custom_timeout_forwarded(self, monkeypatch) -> None:
        captured = self._install_capture(monkeypatch)
        src = HTTPPolicySource("http://example.com/p.json", timeout=42.0)
        src.load()
        assert captured.get("timeout") == 42.0

    def test_allow_redirects_false_forwarded(self, monkeypatch) -> None:
        captured = self._install_capture(monkeypatch)
        src = HTTPPolicySource("http://example.com/p.json", allow_redirects=False)
        src.load()
        assert captured.get("allow_redirects") is False

    def test_all_security_params_forwarded_together(self, monkeypatch) -> None:
        captured = self._install_capture(monkeypatch)
        src = HTTPPolicySource(
            "http://example.com/p.json",
            verify_ssl=False,
            timeout=15.0,
            allow_redirects=False,
        )
        src.load()
        assert captured["verify"] is False
        assert captured["timeout"] == 15.0
        assert captured["allow_redirects"] is False
