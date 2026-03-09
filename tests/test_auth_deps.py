import asyncio
import base64
import json
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from fastapi import HTTPException

from app.auth import deps


def run_async(coro):
    return asyncio.run(coro)


class TestAuthDeps(unittest.TestCase):
    def test_get_authenticated_user_sub_requires_header(self):
        req = SimpleNamespace(headers={})
        with self.assertRaises(HTTPException) as ctx:
            run_async(deps.get_authenticated_user_sub(req))
        self.assertEqual(ctx.exception.status_code, 401)

    def test_get_authenticated_user_sub_rejects_invalid_scheme(self):
        req = SimpleNamespace(headers={"authorization": "Token abc"})
        with self.assertRaises(HTTPException) as ctx:
            run_async(deps.get_authenticated_user_sub(req))
        self.assertEqual(ctx.exception.status_code, 401)

    def test_get_authenticated_user_sub_accepts_bearer(self):
        req = SimpleNamespace(headers={"authorization": "Bearer user-1"})
        user_sub = run_async(deps.get_authenticated_user_sub(req))
        self.assertEqual(user_sub, "user-1")

    def test_get_authenticated_user_sub_prefers_jwt_sub(self):
        header = base64.urlsafe_b64encode(json.dumps({"alg": "none"}).encode()).decode().rstrip("=")
        payload = base64.urlsafe_b64encode(json.dumps({"sub": "jwt-user"}).encode()).decode().rstrip("=")
        token = f"{header}.{payload}."
        req = SimpleNamespace(headers={"authorization": f"Bearer {token}"})
        user_sub = run_async(deps.get_authenticated_user_sub(req))
        self.assertEqual(user_sub, "jwt-user")


    def test_get_authenticated_user_sub_blocks_dev_fallback_when_dev_mode_off(self):
        req = SimpleNamespace(headers={"authorization": "Bearer user-1", "x-user-sub": "user-override"})
        fake_settings = SimpleNamespace(
            cognito_user_pool_id="",
            cognito_app_client_id="",
            dev_mode=False,
        )
        with patch.object(deps, "S", fake_settings):
            with self.assertRaises(HTTPException) as ctx:
                run_async(deps.get_authenticated_user_sub(req))
        self.assertEqual(ctx.exception.status_code, 401)
        self.assertIn("Authentication not configured", str(ctx.exception.detail))


    def test_get_authenticated_user_sub_blocks_banned_user(self):
        req = SimpleNamespace(headers={"authorization": "Bearer user-1"})
        fake_settings = SimpleNamespace(
            cognito_user_pool_id="",
            cognito_app_client_id="",
            dev_mode=True,
        )
        with patch.object(deps, "S", fake_settings), patch.object(deps, "is_user_currently_banned", return_value=True):
            with self.assertRaises(HTTPException) as ctx:
                run_async(deps.get_authenticated_user_sub(req))
        self.assertEqual(ctx.exception.status_code, 403)
