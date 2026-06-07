"""Lock-in regression test for GAP-0322 (PLATFORM-005).

The ticket's premise ("``app/routers/meta.py`` does not exist; there is no
backend meta endpoint") is FALSE as established by the second-pass verification.
The crawler-facing SEO/OpenGraph capability is already built and registered:

* ``app/routers/seo_metadata.py`` (prefix ``/seo``, ``seo_metadata_router``)
  exposes ``GET /seo/metadata`` and ``GET /seo/meta-tags`` -- both accept a
  ``path=``/``url=`` query param and dispatch by URL, OR an explicit
  ``type``+``id``.
* ``app/services/seo_metadata.py`` provides the per-entity builders
  ``_profile_metadata`` / ``_event_metadata`` / ``_post_metadata`` /
  ``_video_metadata`` / ``_live_metadata``, the URL→entity dispatcher
  ``metadata_for_path``, and ``render_meta_tags``.
* The router is registered in ``app/main.py``.

This test locks in:
1. the router is registered on the app with its meta endpoints;
2. all per-entity helpers + ``render_meta_tags`` exist and are callable;
3. the URL-dispatch resolver routes ``/u/...`` -> profile, ``/posts/...`` ->
   post, ``/videos/...`` -> video, ``/event/.../...`` -> event, ``/live/...``
   -> live, dispatching to the correct ``_*_metadata`` helper;
4. the ``url=`` alias (added under this ticket) on the route handlers behaves
   identically to ``path=`` and tolerates a full URL.

Fully offline: the per-entity data loads are stubbed (no DynamoDB / AWS). Async
route handlers are invoked directly (the FastAPI TestClient is unusable here).
"""
from __future__ import annotations

import asyncio
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from app.routers import seo_metadata as router_mod
from app.services import seo_metadata as svc


class _FakeReq:
    """Minimal stand-in for a Starlette Request (only ``base_url`` is used)."""

    base_url = "https://example.test/"


def _run(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


class TestRouterRegistration(unittest.TestCase):
    def test_router_registered_in_main_app(self):
        from app.main import create_app

        app = create_app()
        paths = {getattr(r, "path", None) for r in app.router.routes}
        self.assertIn("/seo/metadata", paths)
        self.assertIn("/seo/meta-tags", paths)

    def test_router_prefix(self):
        self.assertEqual(router_mod.seo_metadata_router.prefix, "/seo")


class TestHelpersExistAndCallable(unittest.TestCase):
    def test_per_entity_helpers_exist(self):
        for name in (
            "_profile_metadata",
            "_event_metadata",
            "_post_metadata",
            "_video_metadata",
            "_live_metadata",
            "render_meta_tags",
            "metadata_for_path",
            "build_metadata",
        ):
            fn = getattr(svc, name, None)
            self.assertTrue(callable(fn), f"{name} missing/not callable")

    def test_render_meta_tags_callable(self):
        # _live_metadata needs no external data, so it's a safe smoke target.
        meta = svc._live_metadata("sess1", "https://example.test")
        html = svc.render_meta_tags(meta)
        self.assertIn("<title>", html)
        self.assertIn("og:title", html)


class TestUrlDispatch(unittest.TestCase):
    """metadata_for_path must route each public URL to the right helper."""

    def test_profile_url_dispatches_to_profile_metadata(self):
        with patch.object(
            svc, "_profile_metadata", return_value={"resource_type": "profile"}
        ) as m:
            out = svc.metadata_for_path("/u/alice", base_url="https://b")
        m.assert_called_once()
        self.assertEqual(m.call_args.args[0], "alice")
        self.assertEqual(out["resource_type"], "profile")

    def test_post_url_dispatches_to_post_metadata(self):
        with patch.object(
            svc, "_post_metadata", return_value={"resource_type": "post"}
        ) as m:
            out = svc.metadata_for_path("/posts/p_abc", base_url="https://b")
        m.assert_called_once()
        self.assertEqual(m.call_args.args[0], "p_abc")
        self.assertEqual(out["resource_type"], "post")

    def test_video_url_dispatches_to_video_metadata(self):
        with patch.object(
            svc, "_video_metadata", return_value={"resource_type": "video"}
        ) as m:
            out = svc.metadata_for_path("/videos/v_xyz", base_url="https://b")
        m.assert_called_once()
        self.assertEqual(m.call_args.args[0], "v_xyz")
        self.assertEqual(out["resource_type"], "video")

    def test_gallery_url_also_dispatches_to_video_metadata(self):
        with patch.object(
            svc, "_video_metadata", return_value={"resource_type": "video"}
        ) as m:
            svc.metadata_for_path("/gallery/v_xyz", base_url="https://b")
        m.assert_called_once()
        self.assertEqual(m.call_args.args[0], "v_xyz")

    def test_event_url_dispatches_to_event_metadata(self):
        with patch.object(
            svc, "_event_metadata", return_value={"resource_type": "event"}
        ) as m:
            svc.metadata_for_path("/event/cal1/evt1", base_url="https://b")
        m.assert_called_once()
        self.assertEqual(m.call_args.args[0], "cal1")
        self.assertEqual(m.call_args.args[1], "evt1")

    def test_live_url_dispatches_to_live_metadata(self):
        with patch.object(
            svc, "_live_metadata", return_value={"resource_type": "live"}
        ) as m:
            svc.metadata_for_path("/live/sess1", base_url="https://b")
        m.assert_called_once()
        self.assertEqual(m.call_args.args[0], "sess1")

    def test_unknown_url_returns_default_unavailable(self):
        out = svc.metadata_for_path("/something/else", base_url="https://b")
        self.assertFalse(out.get("available"))


class TestRouteHandlerUrlAlias(unittest.TestCase):
    """The added ``url=`` param must alias ``path=`` and accept full URLs."""

    def test_metadata_handler_url_param_routes_to_profile(self):
        with patch.object(
            svc, "_profile_metadata", return_value={"resource_type": "profile"}
        ) as m:
            out = _run(
                router_mod.get_seo_metadata(_FakeReq(), path=None, url="/u/alice")
            )
        m.assert_called_once()
        self.assertEqual(m.call_args.args[0], "alice")
        self.assertEqual(out["resource_type"], "profile")

    def test_metadata_handler_full_url_strips_to_path(self):
        with patch.object(
            svc, "_post_metadata", return_value={"resource_type": "post"}
        ) as m:
            _run(
                router_mod.get_seo_metadata(
                    _FakeReq(), path=None, url="https://host.example/posts/p9?x=1#frag"
                )
            )
        m.assert_called_once()
        self.assertEqual(m.call_args.args[0], "p9")

    def test_meta_tags_handler_url_param_renders_html(self):
        with patch.object(
            svc, "_video_metadata", return_value=svc._live_metadata("v1", "https://b")
        ) as m:
            resp = _run(
                router_mod.get_seo_meta_tags(_FakeReq(), path=None, url="/videos/v1")
            )
        m.assert_called_once()
        body = resp.body.decode() if isinstance(resp.body, (bytes, bytearray)) else str(resp.body)
        self.assertIn("<title>", body)

    def test_path_takes_precedence_when_both_given(self):
        with patch.object(
            svc, "_profile_metadata", return_value={"resource_type": "profile"}
        ) as m:
            _run(
                router_mod.get_seo_metadata(
                    _FakeReq(), path="/u/bob", url="/posts/ignored"
                )
            )
        m.assert_called_once()
        self.assertEqual(m.call_args.args[0], "bob")

    def test_no_path_no_url_no_type_returns_default(self):
        out = _run(
            router_mod.get_seo_metadata(
                _FakeReq(), type=None, id=None, secondary_id=None, path=None, url=None
            )
        )
        self.assertFalse(out.get("available"))


class TestResolvePathHelper(unittest.TestCase):
    def test_resolve_path_prefers_path_over_url(self):
        self.assertEqual(router_mod._resolve_path("/u/a", "/posts/b"), "/u/a")

    def test_resolve_path_uses_url_when_no_path(self):
        self.assertEqual(router_mod._resolve_path(None, "/posts/b"), "/posts/b")

    def test_resolve_path_strips_full_url(self):
        self.assertEqual(
            router_mod._resolve_path(None, "https://h/u/alice?q=1"), "/u/alice"
        )

    def test_resolve_path_none_when_neither(self):
        self.assertIsNone(router_mod._resolve_path(None, None))
        self.assertIsNone(router_mod._resolve_path("", "  "))


if __name__ == "__main__":
    unittest.main()
