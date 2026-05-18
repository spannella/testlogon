from __future__ import annotations

import json
import os
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.services.drm_mock_license import issue_entitlement_token, issue_mock_license

MOCK_SECRET = os.getenv("DRM_MOCK_SECRET", "local-dev-secret")


class Handler(BaseHTTPRequestHandler):
    def _json(self, status: int, payload: dict) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_json(self) -> dict:
        size = int(self.headers.get("Content-Length", "0") or "0")
        if size <= 0:
            return {}
        return json.loads(self.rfile.read(size).decode("utf-8"))

    def do_GET(self):  # noqa: N802
        if self.path == "/healthz":
            self._json(200, {"ok": True})
            return
        self._json(404, {"error": "not_found"})

    def do_POST(self):  # noqa: N802
        payload = self._read_json()

        if self.path == "/entitlement":
            try:
                res = issue_entitlement_token(
                    asset_id=str(payload.get("asset_id", "asset_local_demo_001")),
                    tenant_id=str(payload.get("tenant_id", "dev-tenant")),
                    session_id=str(payload.get("session_id", "session-1")),
                    device_id=str(payload.get("device_id", "device-1")),
                    profile=str(payload.get("profile", "multi_drm")),
                    key_id=str(payload.get("key_id", "local-dev-key")),
                    ttl_seconds=int(payload.get("ttl_seconds", 300)),
                    secret=MOCK_SECRET,
                )
                self._json(200, res)
            except Exception as exc:
                self._json(400, {"error": "invalid_entitlement_request", "detail": str(exc)})
            return

        if self.path == "/license":
            auth = self.headers.get("Authorization", "")
            token = payload.get("token") or (auth.split(" ", 1)[1] if auth.startswith("Bearer ") else "")
            try:
                res = issue_mock_license(payload=payload, token=str(token), secret=MOCK_SECRET)
                self._json(200, res)
            except Exception as exc:
                self._json(401, {"error": "license_denied", "detail": str(exc)})
            return

        self._json(404, {"error": "not_found"})


def main() -> None:
    server = HTTPServer(("0.0.0.0", 8090), Handler)
    server.serve_forever()


if __name__ == "__main__":
    main()
