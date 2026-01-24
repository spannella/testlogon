import asyncio
import base64
import json
import unittest
from types import SimpleNamespace

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
