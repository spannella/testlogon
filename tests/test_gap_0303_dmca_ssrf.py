"""Regression test for GAP-0303: DmcaClaimIn.content_url SSRF validation.

Pure pydantic / offline -- no AWS. Verifies that the content_url validator
rejects dangerous schemes and internal/private/loopback/link-local targets,
while still accepting relative paths and public https URLs. Also guards the
pre-existing javascript:/data: rejection.
"""
from __future__ import annotations

import pytest
from pydantic import ValidationError

from app.models import DmcaClaimIn


VALID_BASE = dict(
    claimant_name="Test Claimant",
    claimant_email="test@example.com",
    claimant_address="123 Main St, City, State 00000",
    content_type="feed_post",
    original_work_description="A" * 20,
    sworn_statement=True,
    good_faith_belief=True,
    signature="Test Sig",
)


@pytest.mark.parametrize("url", [
    # SSRF / internal-network targets
    "http://169.254.169.254/latest/meta-data/",        # AWS IMDS / link-local
    "http://169.254.169.254/",
    "http://127.0.0.1/admin",                          # loopback IPv4
    "http://10.0.0.5/internal",                        # RFC-1918 10/8
    "http://192.168.1.1/router",                       # RFC-1918 192.168/16
    "http://172.16.0.1/",                              # RFC-1918 172.16/12
    "http://0.0.0.0/",                                 # unspecified
    "http://[::1]/",                                   # IPv6 loopback
    "http://[fc00::1]/",                               # IPv6 ULA
    "http://localhost/secret",                         # localhost hostname
    "http://localhost.internal/",                      # internal hostname suffix
    "http://foo.local/",                               # .local
    "http://metadata/",                                # metadata hostname
    # Dangerous schemes
    "file:///etc/passwd",
    "ftp://internal.host/secret",
    "gopher://internal:6379/_*1",
    "javascript:alert(1)",
    "data:text/html,<h1>x</h1>",
])
def test_ssrf_and_dangerous_urls_rejected(url):
    with pytest.raises(ValidationError):
        DmcaClaimIn(**VALID_BASE, content_url=url)


@pytest.mark.parametrize("url", [
    "/feed/post/abc123",                               # relative path
    "/videos/xyz789",                                  # relative path
    "https://platform.example.com/feed/post/abc",      # absolute public https
    "http://example.com/feed/post/abc",                # absolute public http
])
def test_valid_urls_accepted(url):
    obj = DmcaClaimIn(**VALID_BASE, content_url=url)
    assert obj.content_url == url.strip()


def test_whitespace_stripped():
    obj = DmcaClaimIn(**VALID_BASE, content_url="  /feed/post/abc  ")
    assert obj.content_url == "/feed/post/abc"
