"""GAP-0323: crawler-detection middleware regression test (offline).

TestClient is broken in this env, so we unit-test the middleware logic directly:
  * the bot-UA detector  (`_is_crawler_ua`)
  * the path-eligibility check (`_is_crawler_eligible_path`)
  * the enable flag (`_crawler_middleware_enabled`)
  * the ASGI dispatch coroutine produced by `_crawler_meta_middleware()` --
    driven with a fake Request + call_next on a fresh event loop, with the
    seo render path stubbed so no DDB/AWS is touched.

No network / AWS / DynamoDB. Run alone:
    .venv/bin/pytest tests/test_gap_0323_crawler_middleware.py -q
"""
from __future__ import annotations

import asyncio
import os
from types import SimpleNamespace

import app.main as m

FACEBOOK_UA = "facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)"
DISCORD_UA = "Discordbot/1.0 (+https://discordapp.com)"
TWITTER_UA = "Twitterbot/1.0"
SLACK_UA = "Slackbot-LinkExpanding 1.0 (+https://api.slack.com/robots)"
GOOGLE_UA = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
BROWSER_UA = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/120.0 Safari/537.36"
)

STUB_TAGS = '<title>Alice</title>\n<meta property="og:title" content="Alice" />'


# ---------------------------------------------------------------------------
# Helper / unit-level checks
# ---------------------------------------------------------------------------
def test_is_crawler_ua_matches_known_bots():
    for ua in (FACEBOOK_UA, DISCORD_UA, TWITTER_UA, SLACK_UA, GOOGLE_UA):
        assert m._is_crawler_ua(ua) is True, ua


def test_is_crawler_ua_rejects_browser_and_empty():
    assert m._is_crawler_ua(BROWSER_UA) is False
    assert m._is_crawler_ua("") is False
    assert m._is_crawler_ua(None) is False  # type: ignore[arg-type]


def test_is_crawler_eligible_path_public_routes():
    for path in (
        "/u/alice",
        "/posts/p_abc123",
        "/event/cal_1/evt_2",
        "/videos/v_9",
        "/live/s_5",
        "/u/alice/",  # trailing slash allowed
    ):
        assert m._is_crawler_eligible_path(path) is True, path


def test_is_crawler_eligible_path_excludes_api_and_private():
    for path in (
        "/api/users",
        "/ui/messaging/conversations",
        "/seo/meta-tags",
        "/internal/ffmpeg-status",
        "/mock/s3/x",
        "/telemetry/log",
        "/static/app.js",
        "/v1/playback/protected",
        "/messages",          # private SPA route, not in public list
        "/",
        "/u/",                # missing identifier
        "/posts/a/b",         # too many segments for /posts
        "",
    ):
        assert m._is_crawler_eligible_path(path) is False, path


def test_crawler_middleware_enabled_flag(monkeypatch):
    monkeypatch.delenv("SEO_CRAWLER_MIDDLEWARE_ENABLED", raising=False)
    assert m._crawler_middleware_enabled() is True  # default on
    for off in ("0", "false", "no", "off", "OFF"):
        monkeypatch.setenv("SEO_CRAWLER_MIDDLEWARE_ENABLED", off)
        assert m._crawler_middleware_enabled() is False, off
    monkeypatch.setenv("SEO_CRAWLER_MIDDLEWARE_ENABLED", "1")
    assert m._crawler_middleware_enabled() is True


# ---------------------------------------------------------------------------
# Fakes for the dispatch coroutine
# ---------------------------------------------------------------------------
class _FakeURL:
    def __init__(self, path: str):
        self.path = path


class _FakeRequest:
    def __init__(self, method: str, path: str, ua: str):
        self.method = method
        self.url = _FakeURL(path)
        self.headers = {"user-agent": ua}
        self.base_url = "http://testserver/"


def _make_call_next():
    state = {"called": False}

    async def _call_next(request):
        state["called"] = True
        return SimpleNamespace(kind="passthrough", status_code=200)

    return _call_next, state


def _run(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


def _stub_seo(monkeypatch):
    """Patch the seo render path (imported lazily inside main) to known HTML."""
    import app.services.seo_metadata as seo

    monkeypatch.setattr(
        seo, "metadata_for_path", lambda path, *, base_url=None: {"path": path}
    )
    monkeypatch.setattr(seo, "render_meta_tags", lambda meta: STUB_TAGS)


# ---------------------------------------------------------------------------
# Dispatch coroutine behaviour
# ---------------------------------------------------------------------------
def test_dispatch_bot_on_page_route_returns_meta_html(monkeypatch):
    monkeypatch.setenv("SEO_CRAWLER_MIDDLEWARE_ENABLED", "1")
    _stub_seo(monkeypatch)
    mw = m._crawler_meta_middleware()
    call_next, state = _make_call_next()

    resp = _run(mw(_FakeRequest("GET", "/u/alice", FACEBOOK_UA), call_next))

    assert state["called"] is False  # short-circuited, call_next NOT called
    assert resp.status_code == 200
    body = resp.body.decode() if isinstance(resp.body, (bytes, bytearray)) else resp.body
    assert 'property="og:title"' in body
    assert "<title>" in body
    assert "<!DOCTYPE html>" in body


def test_dispatch_browser_ua_passes_through(monkeypatch):
    monkeypatch.setenv("SEO_CRAWLER_MIDDLEWARE_ENABLED", "1")
    _stub_seo(monkeypatch)
    mw = m._crawler_meta_middleware()
    call_next, state = _make_call_next()

    resp = _run(mw(_FakeRequest("GET", "/u/alice", BROWSER_UA), call_next))

    assert state["called"] is True
    assert getattr(resp, "kind", None) == "passthrough"


def test_dispatch_bot_on_api_path_passes_through(monkeypatch):
    monkeypatch.setenv("SEO_CRAWLER_MIDDLEWARE_ENABLED", "1")
    _stub_seo(monkeypatch)
    mw = m._crawler_meta_middleware()
    call_next, state = _make_call_next()

    resp = _run(mw(_FakeRequest("GET", "/api/users", FACEBOOK_UA), call_next))

    assert state["called"] is True
    assert getattr(resp, "kind", None) == "passthrough"


def test_dispatch_bot_on_private_spa_route_passes_through(monkeypatch):
    monkeypatch.setenv("SEO_CRAWLER_MIDDLEWARE_ENABLED", "1")
    _stub_seo(monkeypatch)
    mw = m._crawler_meta_middleware()
    call_next, state = _make_call_next()

    resp = _run(mw(_FakeRequest("GET", "/messages", FACEBOOK_UA), call_next))

    assert state["called"] is True


def test_dispatch_non_get_passes_through(monkeypatch):
    monkeypatch.setenv("SEO_CRAWLER_MIDDLEWARE_ENABLED", "1")
    _stub_seo(monkeypatch)
    mw = m._crawler_meta_middleware()
    call_next, state = _make_call_next()

    resp = _run(mw(_FakeRequest("POST", "/u/alice", FACEBOOK_UA), call_next))

    assert state["called"] is True


def test_dispatch_disabled_flag_passes_through(monkeypatch):
    monkeypatch.setenv("SEO_CRAWLER_MIDDLEWARE_ENABLED", "0")
    _stub_seo(monkeypatch)
    mw = m._crawler_meta_middleware()
    call_next, state = _make_call_next()

    resp = _run(mw(_FakeRequest("GET", "/u/alice", FACEBOOK_UA), call_next))

    assert state["called"] is True  # disabled → never intercepts


def test_dispatch_seo_error_falls_through(monkeypatch):
    """A failure in meta rendering must NOT break the request -- fall through."""
    monkeypatch.setenv("SEO_CRAWLER_MIDDLEWARE_ENABLED", "1")
    import app.services.seo_metadata as seo

    def _boom(*a, **k):
        raise RuntimeError("ddb exploded")

    monkeypatch.setattr(seo, "metadata_for_path", _boom)
    mw = m._crawler_meta_middleware()
    call_next, state = _make_call_next()

    resp = _run(mw(_FakeRequest("GET", "/u/alice", FACEBOOK_UA), call_next))

    assert state["called"] is True
    assert getattr(resp, "kind", None) == "passthrough"


def test_middleware_registered_in_app():
    """The crawler middleware is wired into the ASGI stack."""
    app = m.create_app()
    # Starlette stores user middleware in app.user_middleware; the http
    # middleware decorator wraps functions in BaseHTTPMiddleware. We confirm
    # the dispatch closure name appears somewhere in the middleware stack.
    found = False
    for mw in app.user_middleware:
        dispatch = mw.kwargs.get("dispatch") if hasattr(mw, "kwargs") else None
        if dispatch is not None and getattr(dispatch, "__qualname__", "").startswith(
            "_crawler_meta_middleware"
        ):
            found = True
            break
    assert found, "crawler meta middleware not registered in create_app()"
