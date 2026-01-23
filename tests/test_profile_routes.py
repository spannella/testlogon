import asyncio
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from fastapi import HTTPException

from app.models import ProfilePatchReq, ProfilePutReq
from app.routers import profile


def run_async(coro):
    return asyncio.run(coro)


def build_request():
    return SimpleNamespace(headers={"user-agent": "agent"}, client=None, state=SimpleNamespace())


def build_ctx():
    return {"user_sub": "user", "session_id": "sid"}


class TestProfileRoutes(unittest.TestCase):
    def test_get_profile(self):
        ctx = build_ctx()
        with patch.object(profile, "get_profile", return_value={"display_name": "Ada"}):
            resp = run_async(profile.ui_get_profile(ctx=ctx))
        self.assertEqual(resp["profile"]["display_name"], "Ada")

    def test_get_profile_audit(self):
        ctx = build_ctx()
        with patch.object(profile, "get_audit_log", return_value=[{"field": "title"}]):
            resp = run_async(profile.ui_get_profile_audit(ctx=ctx))
        self.assertEqual(resp["audit"], [{"field": "title"}])

    def test_patch_profile_updates(self):
        ctx = build_ctx()
        req = build_request()
        with patch.object(profile, "apply_profile_update", return_value={"display_name": "Ada"}) as apply_mock:
            with patch.object(profile, "audit_event") as audit_mock:
                body = ProfilePatchReq(display_name="Ada")
                resp = run_async(profile.ui_patch_profile(req, body, ctx=ctx))
        apply_mock.assert_called_once_with("user", {"display_name": "Ada"}, replace=False)
        audit_mock.assert_called_once()
        self.assertEqual(resp["profile"]["display_name"], "Ada")

    def test_put_profile_replaces(self):
        ctx = build_ctx()
        req = build_request()
        with patch.object(profile, "apply_profile_update", return_value={"display_name": "Grace"}) as apply_mock:
            with patch.object(profile, "audit_event") as audit_mock:
                body = ProfilePutReq(display_name="Grace")
                resp = run_async(profile.ui_put_profile(req, body, ctx=ctx))
        apply_mock.assert_called_once()
        _, payload = apply_mock.call_args.args[:2]
        self.assertEqual(apply_mock.call_args.kwargs.get("replace"), True)
        self.assertEqual(payload["display_name"], "Grace")
        audit_mock.assert_called_once()
        self.assertEqual(resp["profile"]["display_name"], "Grace")

    def test_upload_photo_requires_multipart(self):
        ctx = build_ctx()
        if profile._MULTIPART_AVAILABLE:
            self.skipTest("python-multipart is installed; upload route is available")
        with self.assertRaises(HTTPException) as exc:
            run_async(profile.ui_upload_profile_photo_unavailable(ctx=ctx))
        self.assertEqual(exc.exception.status_code, 501)

    def test_profile_patch_put_flow_updates_state(self):
        ctx = build_ctx()
        req = build_request()
        store = {"profile": {}, "audit": []}

        def fake_get_profile(user_sub):
            return store["profile"]

        def fake_apply_profile_update(user_sub, updates, *, replace):
            if replace:
                store["profile"] = dict(updates)
            else:
                store["profile"].update(updates)
            store["audit"].append({"field": "display_name", "to": store["profile"].get("display_name")})
            return store["profile"]

        def fake_get_audit_log(user_sub):
            return list(store["audit"])

        with patch.object(profile, "get_profile", side_effect=fake_get_profile):
            with patch.object(profile, "apply_profile_update", side_effect=fake_apply_profile_update):
                with patch.object(profile, "get_audit_log", side_effect=fake_get_audit_log):
                    with patch.object(profile, "audit_event"):
                        run_async(profile.ui_patch_profile(req, ProfilePatchReq(display_name="Ada"), ctx=ctx))
                        run_async(profile.ui_put_profile(req, ProfilePutReq(display_name="Grace"), ctx=ctx))
                        get_resp = run_async(profile.ui_get_profile(ctx=ctx))
                        audit_resp = run_async(profile.ui_get_profile_audit(ctx=ctx))

        self.assertEqual(get_resp["profile"]["display_name"], "Grace")
        self.assertEqual(len(audit_resp["audit"]), 2)
