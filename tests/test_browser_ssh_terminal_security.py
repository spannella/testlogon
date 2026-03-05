from __future__ import annotations

import json
import logging

from fastapi.testclient import TestClient

from app.main import create_app
from app.routers import browser_ssh_terminal


class _NeverConnectBridge:
    def connect(self) -> None:  # pragma: no cover - should never be called
        raise AssertionError("Bridge must not be created for policy-denied destinations")

    def poll_output(self) -> str:
        return ""

    def send_input(self, data: str) -> None:
        return None

    def resize(self, cols: int, rows: int) -> None:
        return None

    def close(self) -> None:
        return None


class _SimpleBridge:
    def __init__(self) -> None:
        self.closed = False

    def connect(self) -> None:
        return None

    def poll_output(self) -> str:
        return ""

    def send_input(self, data: str) -> None:
        return None

    def resize(self, cols: int, rows: int) -> None:
        return None

    def close(self) -> None:
        self.closed = True


def _allow_terminal_ws_access(monkeypatch) -> None:
    async def _allow(_websocket):
        return {"user_sub": "sec-user", "role": "admin"}, None

    monkeypatch.setattr(browser_ssh_terminal, "_authorize_terminal_access", _allow)


def test_redact_connect_payload_masks_secret_fields() -> None:
    redacted = browser_ssh_terminal._redact_connect_payload(
        {
            "host": "example.internal",
            "port": 22,
            "username": "alice",
            "authType": "private_key",
            "password": "supersecret",
            "privateKey": "-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n-----END OPENSSH PRIVATE KEY-----",
            "passphrase": "hunter2",
        }
    )

    assert redacted["password"] == "***REDACTED***"
    assert redacted["passphrase"] == "***REDACTED***"
    assert "REDACTED" in redacted["privateKey"]
    assert "supersecret" not in json.dumps(redacted)
    assert "hunter2" not in json.dumps(redacted)


def test_policy_denied_destination_blocks_bridge_creation(monkeypatch) -> None:
    _allow_terminal_ws_access(monkeypatch)
    monkeypatch.setenv("BROWSER_SSH_DENIED_HOSTS", "blocked.internal")
    monkeypatch.setattr(browser_ssh_terminal, "_create_ssh_bridge", lambda *_: _NeverConnectBridge())

    app = create_app()
    client = TestClient(app)

    with client.websocket_connect("/api/browser-ssh/ws") as ws:
        _ = ws.receive_json()
        ws.send_json(
            {
                "type": "connect",
                "payload": {
                    "host": "blocked.internal",
                    "port": 22,
                    "username": "alice",
                    "authType": "password",
                    "password": "secret",
                },
            }
        )
        err = ws.receive_json()
        assert err["type"] == "error"
        assert err["payload"]["code"] == "policy_denied_host"


def test_websocket_connect_logging_redacts_password(monkeypatch, caplog) -> None:
    _allow_terminal_ws_access(monkeypatch)
    monkeypatch.setattr(browser_ssh_terminal, "_create_ssh_bridge", lambda *_: _SimpleBridge())
    caplog.set_level(logging.INFO, logger="app.routers.browser_ssh_terminal")

    app = create_app()
    client = TestClient(app)

    with client.websocket_connect("/api/browser-ssh/ws") as ws:
        _ = ws.receive_json()
        ws.send_json(
            {
                "type": "connect",
                "payload": {
                    "host": "safe.internal",
                    "port": 22,
                    "username": "alice",
                    "authType": "password",
                    "password": "ultra-secret",
                },
            }
        )
        status = ws.receive_json()
        assert status["type"] == "status"
        assert status["payload"]["phase"] == "connected"

    connect_records = [record for record in caplog.records if hasattr(record, "connect")]
    assert connect_records
    assert all("ultra-secret" not in repr(getattr(record, "connect", {})) for record in connect_records)
