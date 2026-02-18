import asyncio
import unittest

from starlette.requests import Request
from starlette.responses import Response

from app.main import _security_headers_middleware
from app.core.settings import Settings


class TestMainSecurityHeaders(unittest.TestCase):
    def test_security_middleware_sets_expected_headers(self):
        async def call_next(_request: Request) -> Response:
            return Response("ok")

        scope = {
            "type": "http",
            "method": "GET",
            "path": "/",
            "headers": [],
            "client": ("127.0.0.1", 12345),
            "server": ("test", 80),
            "scheme": "http",
            "query_string": b"",
        }
        req = Request(scope)
        middleware = _security_headers_middleware("default-src 'self'")
        resp = asyncio.run(middleware(req, call_next))

        self.assertEqual(resp.headers.get("Content-Security-Policy"), "default-src 'self'")
        self.assertEqual(resp.headers.get("X-Content-Type-Options"), "nosniff")
        self.assertEqual(resp.headers.get("X-Frame-Options"), "DENY")
        self.assertEqual(resp.headers.get("Referrer-Policy"), "strict-origin-when-cross-origin")

    def test_default_csp_includes_preview_hardening_directives(self):
        csp = Settings().security_csp_header
        self.assertIn("script-src 'self'", csp)
        self.assertIn("object-src 'none'", csp)
        self.assertIn("frame-src 'self' blob:", csp)
        self.assertIn("worker-src 'self' blob:", csp)
        self.assertIn("form-action 'self'", csp)


if __name__ == "__main__":
    unittest.main()
