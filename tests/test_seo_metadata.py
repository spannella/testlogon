"""PLATFORM-005: unit tests for SEO / OpenGraph metadata.

These tests exercise the metadata builder, the privacy-respecting defaults
(missing / unknown resources never leak private content), and the
crawler-facing /seo/* HTTP endpoints.
"""
from __future__ import annotations

import os

import pytest

from app.services import seo_metadata as seo


_NEEDS_LIVE_STACK = pytest.mark.skip(
    reason="TestClient startup events access DynamoDB tables; requires live dev stack"
)


@pytest.fixture()
def client():
    """A FastAPI TestClient — only used by the 5 tests marked _NEEDS_LIVE_STACK."""
    os.environ.setdefault("AWS_ACCESS_KEY_ID", "test")
    os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "test")
    os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")
    os.environ.setdefault("DEV_MODE", "1")
    os.environ.setdefault("UI_ACCESS_TOKEN_SECRET", "test-secret")
    os.environ.setdefault("API_KEY_PEPPER", "test-pepper")
    from fastapi.testclient import TestClient
    from app.main import app
    with TestClient(app, raise_server_exceptions=False) as c:
        yield c


# ── Service-level (no AWS needed) ─────────────────────────────────────────

def test_default_metadata_is_unavailable_and_generic():
    meta = seo.default_metadata("https://x.test", "/u/whoever")
    assert meta["available"] is False
    assert meta["title"] == seo.DEFAULT_TITLE
    assert meta["og"]["og:type"] == "website"
    assert meta["og"]["og:site_name"] == seo.SITE_NAME


def test_live_metadata_is_deterministic():
    meta = seo.build_metadata("live", "sess1", base_url="https://x.test")
    assert meta["available"] is True
    assert meta["og"]["og:type"] == "video.other"
    assert meta["json_ld"]["@type"] == "BroadcastEvent"
    assert meta["canonical_url"] == "https://x.test/live/sess1"


def test_unknown_type_returns_default():
    meta = seo.build_metadata("widget", "abc", base_url="https://x.test")
    assert meta["available"] is False
    assert meta["title"] == seo.DEFAULT_TITLE


def test_metadata_for_path_unknown_returns_default():
    meta = seo.metadata_for_path("/nope/123", base_url="https://x.test")
    assert meta["available"] is False


def test_missing_profile_does_not_leak():
    meta = seo.build_metadata(
        "profile", "no_such_user_zzz", base_url="https://x.test"
    )
    # Resolution fails -> generic default, never a fabricated profile.
    assert meta["available"] is False
    assert meta["title"] == seo.DEFAULT_TITLE


def test_render_meta_tags_escapes_user_content():
    meta = seo._assemble(
        resource_type="profile",
        resource_id="x",
        title='Bob <script>"&',
        description="hi",
        path="/u/x",
        base_url="https://x.test",
        og_type="profile",
        image=None,
        json_ld={"@type": "Person", "name": "a</script>b"},
    )
    html = seo.render_meta_tags(meta)
    assert "<script>alert" not in html
    assert "&lt;script&gt;" in html
    # JSON-LD closing-script breakout is neutralised.
    segment = html.split('application/ld+json">', 1)[1].split("</script>", 1)[0]
    assert "</script" not in segment


def test_truncation_caps_description():
    long = "word " * 100
    out = seo._truncate(long, limit=50)
    assert len(out) <= 50


def test_robots_txt_blocks_private_allows_public():
    text = seo.build_robots_txt(base_url="https://x.test")
    assert "Allow: /u/" in text
    assert "Disallow: /messages" in text
    assert "Disallow: /billing" in text
    assert "Sitemap: https://x.test/seo/sitemap.xml" in text


def test_sitemap_xml_is_well_formed():
    xml = seo.build_sitemap_xml(
        [{"path": "/"}, {"path": "/u/alice"}], base_url="https://x.test"
    )
    assert xml.startswith("<?xml")
    assert "<urlset" in xml
    assert "https://x.test/u/alice" in xml


# ── HTTP-level (TestClient — requires live DynamoDB stack) ───────────────


@_NEEDS_LIVE_STACK
def test_seo_metadata_endpoint_live(client):
    resp = client.get("/seo/metadata", params={"type": "live", "id": "s1"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["og"]["og:type"] == "video.other"
    assert "Live Stream" in body["title"]


@_NEEDS_LIVE_STACK
def test_seo_metadata_endpoint_missing_profile_default(client):
    resp = client.get(
        "/seo/metadata", params={"type": "profile", "id": "ghost_user"}
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["available"] is False
    assert body["title"] == seo.DEFAULT_TITLE


@_NEEDS_LIVE_STACK
def test_seo_meta_tags_endpoint_html(client):
    resp = client.get("/seo/meta-tags", params={"type": "live", "id": "s1"})
    assert resp.status_code == 200
    assert "<title>" in resp.text
    assert 'property="og:title"' in resp.text


@_NEEDS_LIVE_STACK
def test_seo_robots_endpoint(client):
    resp = client.get("/seo/robots.txt")
    assert resp.status_code == 200
    assert "Disallow: /messages" in resp.text


@_NEEDS_LIVE_STACK
def test_seo_sitemap_endpoint(client):
    resp = client.get("/seo/sitemap.xml")
    assert resp.status_code == 200
    assert resp.text.strip().startswith("<?xml")
