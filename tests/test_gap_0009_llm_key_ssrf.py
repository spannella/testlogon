"""GAP-0009 regression: LLM provider key base_url SSRF protection.

Offline test (no AWS, no network). The base_url validator on
LlmKeyCreateIn must reject SSRF-prone URLs (metadata/RFC-1918/loopback,
non-HTTPS) and accept normal public HTTPS URLs.
"""
import pytest
from pydantic import ValidationError

from app.models import LlmKeyCreateIn


def _make(base_url: str) -> LlmKeyCreateIn:
    return LlmKeyCreateIn(
        provider="custom",
        label="test",
        api_key="sk-test12345678",
        base_url=base_url,
    )


@pytest.mark.parametrize(
    "bad_url",
    [
        "http://169.254.169.254/",            # EC2 IMDS / link-local
        "http://169.254.169.254/latest/meta-data/",
        "http://10.0.0.1/admin",              # RFC-1918 (http)
        "http://192.168.1.1/",                # RFC-1918 (http)
        "http://172.16.0.1/",                 # RFC-1918 (http)
    ],
)
def test_rejects_ssrf_base_url(bad_url):
    # These http:// non-localhost URLs are rejected regardless of dev_mode:
    # non-localhost http fails the HTTPS-only check, and the metadata/RFC-1918
    # IPs are in the blocked ranges.
    with pytest.raises(ValidationError):
        _make(bad_url)


def test_accepts_https_public_base_url():
    model = _make("https://my-proxy.example.com/v1")
    assert model.base_url == "https://my-proxy.example.com/v1"


def test_empty_base_url_ok():
    model = LlmKeyCreateIn(
        provider="openai",
        label="test",
        api_key="sk-test12345678",
    )
    assert model.base_url == ""
