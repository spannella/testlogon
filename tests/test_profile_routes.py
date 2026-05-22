import asyncio
import json
import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from fastapi import HTTPException

from app.auth.deps import AuthenticatedUser
from app.models import ProfilePatchReq, ProfilePutReq
from app.routers import profile


def run_async(coro):
    return asyncio.run(coro)


def build_request():
    return SimpleNamespace(headers={"user-agent": "agent"}, client=None, state=SimpleNamespace())


def build_ctx():
    return {"user_sub": "user", "session_id": "sid"}


class TestProfileRoutes(unittest.TestCase):
    def setUp(self):
        profile._clear_profile_identifier_cache()

    def tearDown(self):
        profile._clear_profile_identifier_cache()

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

    def test_get_profile_by_identifier_as_public(self):
        req = build_request()
        with patch.object(profile, "S", SimpleNamespace(profile_lookup_audience_filtering_enabled=True)):
            with patch.object(profile, "_resolve_profile_identifier_to_user_sub", return_value="target_1"):
                with patch.object(profile, "require_ui_session", side_effect=HTTPException(status_code=401, detail="unauthorized")):
                    with patch.object(profile, "rate_limit_profile_lookup") as rl_mock:
                        with patch.object(profile, "client_ip_from_request", return_value="198.51.100.8"):
                            with patch.object(profile, "get_profile_discoverability_state", return_value={"discoverability_status": "active"}):
                                with patch.object(profile, "get_profile_for_requester", return_value={"display_name": "Ada"}) as get_for_requester:
                                    resp = run_async(profile.ui_get_profile_by_identifier("target_1", req))
        rl_mock.assert_called_once_with(None, "198.51.100.8")
        get_for_requester.assert_called_once_with(target_user_sub="target_1", requester_user_sub=None)
        payload = json.loads(resp.body)
        self.assertEqual(payload["identifier"], "target_1")
        self.assertEqual(payload["user_sub"], "target_1")
        self.assertEqual(payload["audience"], "public")
        self.assertEqual(payload["profile"]["display_name"], "Ada")

    def test_get_profile_by_identifier_as_member(self):
        req = build_request()
        with patch.object(profile, "S", SimpleNamespace(profile_lookup_audience_filtering_enabled=True)):
            with patch.object(profile, "_resolve_profile_identifier_to_user_sub", return_value="target_1"):
                with patch.object(profile, "get_authenticated_user", AsyncMock(return_value=AuthenticatedUser(sub="viewer_1"))):
                    with patch.object(profile, "require_ui_session", return_value={"user_sub": "viewer_1", "session_id": "sid"}):
                        with patch.object(profile, "rate_limit_profile_lookup") as rl_mock:
                            with patch.object(profile, "client_ip_from_request", return_value="198.51.100.9"):
                                with patch.object(profile, "get_profile_discoverability_state", return_value={"discoverability_status": "active"}):
                                    with patch.object(profile, "get_profile_for_requester", return_value={"display_name": "Ada"}) as get_for_requester:
                                        resp = run_async(profile.ui_get_profile_by_identifier("target_1", req))
        rl_mock.assert_called_once_with("viewer_1", "198.51.100.9")
        get_for_requester.assert_called_once_with(target_user_sub="target_1", requester_user_sub="viewer_1")
        payload = json.loads(resp.body)
        self.assertEqual(payload["audience"], "member")

    def test_get_profile_by_identifier_not_found(self):
        req = build_request()
        with patch.object(profile, "rate_limit_profile_lookup"):
            with patch.object(profile, "_resolve_profile_identifier_to_user_sub", side_effect=HTTPException(status_code=404, detail="Profile not found")):
                with self.assertRaises(HTTPException) as exc:
                    run_async(profile.ui_get_profile_by_identifier("missing", req))
        self.assertEqual(exc.exception.status_code, 404)

    def test_get_profile_by_identifier_propagates_suppressed_not_found(self):
        req = build_request()
        with patch.object(profile, "S", SimpleNamespace(profile_lookup_audience_filtering_enabled=True)):
            with patch.object(profile, "rate_limit_profile_lookup"):
                with patch.object(profile, "_resolve_profile_identifier_to_user_sub", return_value="target_1"):
                    with patch.object(profile, "require_ui_session", return_value={"user_sub": "viewer_1", "session_id": "sid"}):
                        with patch.object(profile, "get_profile_discoverability_state", return_value={"discoverability_status": "hidden"}):
                            with patch.object(
                                profile,
                                "get_profile_for_requester",
                                side_effect=HTTPException(status_code=404, detail="Profile not found"),
                            ):
                                with self.assertRaises(HTTPException) as exc:
                                    run_async(profile.ui_get_profile_by_identifier("target_1", req))
        self.assertEqual(exc.exception.status_code, 404)

    def test_get_profile_by_identifier_rate_limited_returns_non_leaky_error(self):
        req = build_request()
        with patch.object(profile, "_resolve_profile_identifier_to_user_sub", return_value="target_1"):
            with patch.object(profile, "require_ui_session", side_effect=HTTPException(status_code=401, detail="unauthorized")):
                with patch.object(
                    profile,
                    "rate_limit_profile_lookup",
                    side_effect=HTTPException(status_code=429, detail={"code": "profile_lookup_rate_limited", "tier": "anonymous"}),
                ):
                    with self.assertRaises(HTTPException) as exc:
                        run_async(profile.ui_get_profile_by_identifier("target_1", req))
        self.assertEqual(exc.exception.status_code, 429)
        self.assertEqual(exc.exception.detail["code"], "profile_lookup_rate_limited")

    def test_unknown_and_suppressed_lookup_share_same_not_found_detail(self):
        req = build_request()
        with patch.object(profile, "rate_limit_profile_lookup"):
            with patch.object(profile, "_resolve_profile_identifier_to_user_sub", side_effect=HTTPException(status_code=404, detail="Profile not found")):
                with self.assertRaises(HTTPException) as unknown_exc:
                    run_async(profile.ui_get_profile_by_identifier("unknown_user", req))

        with patch.object(profile, "S", SimpleNamespace(profile_lookup_audience_filtering_enabled=True)):
            with patch.object(profile, "rate_limit_profile_lookup"):
                with patch.object(profile, "_resolve_profile_identifier_to_user_sub", return_value="target_1"):
                    with patch.object(profile, "require_ui_session", side_effect=HTTPException(status_code=401, detail="unauthorized")):
                        with patch.object(profile, "get_profile_discoverability_state", return_value={"discoverability_status": "hidden"}):
                            with patch.object(
                                profile,
                                "get_profile_for_requester",
                                side_effect=HTTPException(status_code=404, detail="Profile not found"),
                            ):
                                with self.assertRaises(HTTPException) as suppressed_exc:
                                    run_async(profile.ui_get_profile_by_identifier("target_1", req))

        self.assertEqual(unknown_exc.exception.status_code, 404)
        self.assertEqual(suppressed_exc.exception.status_code, 404)
        self.assertEqual(unknown_exc.exception.detail, suppressed_exc.exception.detail)

    def test_profile_lookup_records_not_found_metric_for_unknown_identifier(self):
        req = build_request()
        with patch.object(profile, "rate_limit_profile_lookup"):
            with patch.object(profile, "record_profile_lookup") as metrics_mock:
                with patch.object(profile, "_resolve_profile_identifier_to_user_sub", side_effect=HTTPException(status_code=404, detail="Profile not found")):
                    with self.assertRaises(HTTPException):
                        run_async(profile.ui_get_profile_by_identifier("unknown_user", req))
        kwargs = metrics_mock.call_args.kwargs
        self.assertEqual(kwargs["result"], "not_found")
        self.assertEqual(kwargs["suppression_reason"], "none")

    def test_profile_lookup_records_denied_metric_for_suppressed_identifier(self):
        req = build_request()
        with patch.object(profile, "S", SimpleNamespace(profile_lookup_audience_filtering_enabled=True)):
            with patch.object(profile, "rate_limit_profile_lookup"):
                with patch.object(profile, "record_profile_lookup") as metrics_mock:
                    with patch.object(profile, "_resolve_profile_identifier_to_user_sub", return_value="target_1"):
                        with patch.object(profile, "require_ui_session", side_effect=HTTPException(status_code=401, detail="unauthorized")):
                            with patch.object(profile, "get_profile_discoverability_state", return_value={"discoverability_status": "hidden"}):
                                with patch.object(
                                    profile,
                                    "get_profile_for_requester",
                                    side_effect=HTTPException(status_code=404, detail="Profile not found"),
                                ):
                                    with self.assertRaises(HTTPException):
                                        run_async(profile.ui_get_profile_by_identifier("target_1", req))
        kwargs = metrics_mock.call_args.kwargs
        self.assertEqual(kwargs["result"], "denied")
        self.assertEqual(kwargs["suppression_reason"], "hidden")

    def test_resolve_profile_identifier_to_user_sub_direct_lookup(self):
        users_tbl = SimpleNamespace(
            get_item=lambda Key: {"Item": {"user_sub": Key["user_sub"]}},
            scan=lambda **kwargs: {"Items": []},
        )
        with patch.object(profile, "T", SimpleNamespace(users=users_tbl)):
            with patch.object(profile, "record_profile_lookup_identifier_resolution") as metric_mock:
                out = profile._resolve_profile_identifier_to_user_sub("u_direct")
        self.assertEqual(out, "u_direct")
        metric_mock.assert_called_once_with(source="direct", outcome="resolved")

    def test_resolve_profile_identifier_to_user_sub_alias_lookup(self):
        users_tbl = SimpleNamespace(
            get_item=lambda Key: {},
            scan=lambda **kwargs: {"Items": [{"user_sub": "u_alias", "username": "ada"}]},
        )
        with patch.object(profile, "T", SimpleNamespace(users=users_tbl)):
            out = profile._resolve_profile_identifier_to_user_sub("ada")
        self.assertEqual(out, "u_alias")

    def test_resolve_profile_identifier_uses_cache_for_repeat_lookups(self):
        calls = {"get_item": 0, "scan": 0}

        def _get_item(Key):
            calls["get_item"] += 1
            return {}

        def _scan(**kwargs):
            calls["scan"] += 1
            return {"Items": [{"user_sub": "u_cached", "username": "ada"}]}

        users_tbl = SimpleNamespace(get_item=_get_item, scan=_scan)
        with patch.object(profile, "T", SimpleNamespace(users=users_tbl)):
            first = profile._resolve_profile_identifier_to_user_sub("ada")
            second = profile._resolve_profile_identifier_to_user_sub("ada")
        self.assertEqual(first, "u_cached")
        self.assertEqual(second, "u_cached")
        self.assertEqual(calls["get_item"], 1)
        self.assertEqual(calls["scan"], 1)

    def test_resolve_profile_identifier_cache_entry_expires(self):
        calls = {"get_item": 0, "scan": 0}

        def _get_item(Key):
            calls["get_item"] += 1
            return {}

        def _scan(**kwargs):
            calls["scan"] += 1
            return {"Items": [{"user_sub": "u_expire", "username": "ada"}]}

        users_tbl = SimpleNamespace(get_item=_get_item, scan=_scan)
        with patch.object(profile, "_PROFILE_IDENTIFIER_CACHE_TTL_SECONDS", 0.0):
            with patch.object(profile, "T", SimpleNamespace(users=users_tbl)):
                first = profile._resolve_profile_identifier_to_user_sub("ada")
                second = profile._resolve_profile_identifier_to_user_sub("ada")

        self.assertEqual(first, "u_expire")
        self.assertEqual(second, "u_expire")
        self.assertEqual(calls["get_item"], 2)
        self.assertEqual(calls["scan"], 2)

    def test_resolve_profile_identifier_negative_cache_avoids_repeat_scans(self):
        calls = {"get_item": 0, "scan": 0}

        def _get_item(Key):
            calls["get_item"] += 1
            return {}

        def _scan(**kwargs):
            calls["scan"] += 1
            return {"Items": []}

        users_tbl = SimpleNamespace(get_item=_get_item, scan=_scan)
        with patch.object(profile, "record_profile_lookup_identifier_resolution") as metric_mock:
            with patch.object(profile, "T", SimpleNamespace(users=users_tbl)):
                with self.assertRaises(HTTPException) as first_exc:
                    profile._resolve_profile_identifier_to_user_sub("missing_alias")
                with self.assertRaises(HTTPException) as second_exc:
                    profile._resolve_profile_identifier_to_user_sub("missing_alias")

        self.assertEqual(first_exc.exception.status_code, 404)
        self.assertEqual(second_exc.exception.status_code, 404)
        self.assertEqual(calls["get_item"], 1)
        self.assertEqual(calls["scan"], 1)
        self.assertEqual(
            [call.kwargs for call in metric_mock.call_args_list],
            [
                {"source": "alias_scan", "outcome": "not_found"},
                {"source": "cache", "outcome": "negative_hit"},
            ],
        )

    def test_resolve_profile_identifier_negative_cache_expires(self):
        calls = {"get_item": 0, "scan": 0}

        def _get_item(Key):
            calls["get_item"] += 1
            return {}

        def _scan(**kwargs):
            calls["scan"] += 1
            return {"Items": []}

        users_tbl = SimpleNamespace(get_item=_get_item, scan=_scan)
        with patch.object(profile, "_PROFILE_IDENTIFIER_NEGATIVE_CACHE_TTL_SECONDS", 0.0):
            with patch.object(profile, "T", SimpleNamespace(users=users_tbl)):
                with self.assertRaises(HTTPException):
                    profile._resolve_profile_identifier_to_user_sub("missing_alias")
                with self.assertRaises(HTTPException):
                    profile._resolve_profile_identifier_to_user_sub("missing_alias")

        self.assertEqual(calls["get_item"], 2)
        self.assertEqual(calls["scan"], 2)

    def test_resolve_profile_identifier_skips_alias_scan_for_invalid_identifier_shape(self):
        calls = {"get_item": 0, "scan": 0}

        def _get_item(Key):
            calls["get_item"] += 1
            return {}

        def _scan(**kwargs):
            calls["scan"] += 1
            return {"Items": []}

        users_tbl = SimpleNamespace(get_item=_get_item, scan=_scan)
        with patch.object(profile, "record_profile_lookup_identifier_resolution") as metric_mock:
            with patch.object(profile, "T", SimpleNamespace(users=users_tbl)):
                with self.assertRaises(HTTPException) as exc:
                    profile._resolve_profile_identifier_to_user_sub("bad alias with spaces")

        self.assertEqual(exc.exception.status_code, 404)
        self.assertEqual(calls["get_item"], 1)
        self.assertEqual(calls["scan"], 0)
        metric_mock.assert_called_once_with(source="alias_scan", outcome="skipped_invalid_identifier")

    def test_resolve_canonical_identifier_prefers_username_then_handle(self):
        users_tbl = SimpleNamespace(
            get_item=lambda Key: {"Item": {"user_sub": Key["user_sub"], "username": "ada.username", "handle": "ada_handle"}},
        )
        with patch.object(profile, "T", SimpleNamespace(users=users_tbl)):
            out = profile._resolve_canonical_identifier_for_user_sub("u_ada")
        self.assertEqual(out, "ada.username")

    def test_resolve_canonical_identifier_falls_back_to_handle_and_user_sub(self):
        users_tbl_handle = SimpleNamespace(
            get_item=lambda Key: {"Item": {"user_sub": Key["user_sub"], "username": "", "handle": "ada_handle"}},
        )
        with patch.object(profile, "T", SimpleNamespace(users=users_tbl_handle)):
            out_handle = profile._resolve_canonical_identifier_for_user_sub("u_ada")
        self.assertEqual(out_handle, "ada_handle")

        users_tbl_user_sub = SimpleNamespace(
            get_item=lambda Key: {"Item": {"user_sub": Key["user_sub"], "username": "bad alias with spaces", "handle": ""}},
        )
        with patch.object(profile, "T", SimpleNamespace(users=users_tbl_user_sub)):
            out_user_sub = profile._resolve_canonical_identifier_for_user_sub("u_ada")
        self.assertEqual(out_user_sub, "u_ada")

    def test_resolve_canonical_identifier_falls_back_when_table_lookup_errors(self):
        users_tbl = SimpleNamespace(
            get_item=lambda Key: (_ for _ in ()).throw(RuntimeError("ddb unavailable")),
        )
        with patch.object(profile, "T", SimpleNamespace(users=users_tbl)):
            out = profile._resolve_canonical_identifier_for_user_sub("u_ada")
        self.assertEqual(out, "u_ada")

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
